package com.commafinder;

import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorCompletionService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.function.IntConsumer;

/**
 * 서브넷의 .1 ~ .254 를 스캔한다.
 *
 * 변경점 (v1.71 대비):
 *  - 포트가 열린 것만으로 "발견"으로 확정하지 않고, Verifier 로 comma 기기인지 확인한다.
 *    (기존: 가장 먼저 포트가 열린 호스트 = 결과 → 헤드유닛이 먼저 응답하면 헤드유닛이 잡힘)
 *  - 내 폰 자신의 IP 는 후보에서 제외한다.
 *
 * 공개 API(생성자, scan, cancel, Result, Status)는 기존과 동일하다.
 */
public class PortScanner {

    /** 포트가 열린 호스트가 진짜 comma 기기인지 판별한다. 워커 스레드에서 호출됨(블로킹 허용). */
    public interface Verifier {
        boolean verify(String ip, int port);
    }

    public enum Status { FOUND, NOT_FOUND, CANCELLED }

    public record Result(Status status, String ip) {
        public static Result found(String ip) { return new Result(Status.FOUND, ip); }
        public static Result notFound()       { return new Result(Status.NOT_FOUND, null); }
        public static Result cancelled()      { return new Result(Status.CANCELLED, null); }
    }

    private static final int FIRST_HOST = 1;
    private static final int LAST_HOST = 254;

    private final int threadCount;
    private final int timeoutMs;
    private volatile boolean cancelled;
    private volatile ExecutorService executor;
    private volatile Verifier verifier;                       // null 이면 기존 동작(검증 없음)
    private volatile Set<String> excludedHosts = new HashSet<>();

    public PortScanner(int threadCount, int timeoutMs) {
        this.threadCount = threadCount;
        this.timeoutMs = timeoutMs;
    }

    public PortScanner setVerifier(Verifier verifier) {
        this.verifier = verifier;
        return this;
    }

    /** 스캔 후보에서 뺄 IP (예: 내 폰의 IP). */
    public PortScanner setExcludedHosts(Collection<String> hosts) {
        this.excludedHosts = new HashSet<>(hosts);
        return this;
    }

    public void cancel() {
        cancelled = true;
        ExecutorService ex = executor;
        if (ex != null) ex.shutdownNow();
    }

    public Result scan(List<String> subnets, int port, IntConsumer progress) {
        if (cancelled) return Result.cancelled();

        ExecutorService pool = Executors.newFixedThreadPool(threadCount);
        executor = pool;
        ExecutorCompletionService<String> cs = new ExecutorCompletionService<>(pool);
        final Verifier v = verifier;
        final Set<String> excluded = excludedHosts;

        int submitted = 0;
        int done = 0;
        try {
            for (String subnet : subnets) {
                for (int host = FIRST_HOST; host <= LAST_HOST; host++) {
                    final String ip = subnet + "." + host;
                    cs.submit((Callable<String>) () -> probe(ip, port, v, excluded));
                    submitted++;
                }
            }
            while (done < submitted && !cancelled) {
                Future<String> f = cs.poll(50, TimeUnit.MILLISECONDS);
                if (f == null) continue;
                done++;
                progress.accept(done);
                String hit = f.get();
                if (hit != null) return Result.found(hit);
            }
            return cancelled ? Result.cancelled() : Result.notFound();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return Result.cancelled();
        } catch (ExecutionException e) {
            return cancelled ? Result.cancelled() : Result.notFound();
        } finally {
            pool.shutdownNow();
            if (executor == pool) executor = null;
        }
    }

    private String probe(String ip, int port, Verifier v, Set<String> excluded) {
        if (cancelled || excluded.contains(ip)) return null;
        if (!NetworkUtils.isPortOpen(ip, port, timeoutMs)) return null;
        if (v != null && !v.verify(ip, port)) return null;   // ← 헤드유닛 등은 여기서 탈락
        return ip;
    }
}
