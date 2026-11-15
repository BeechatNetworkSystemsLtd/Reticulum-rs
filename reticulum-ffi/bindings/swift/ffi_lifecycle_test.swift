import Foundation

final class LifecycleReconciler: AppReconciler, @unchecked Sendable {
    let sem: DispatchSemaphore
    init(_ sem: DispatchSemaphore) {
        self.sem = sem
    }
    func reconcile(update: AppUpdate) {
        if case .fullState(let state) = update {
            if case .running = state.status {
                sem.signal()
            }
        }
    }
}

@main
struct LifecycleTest {
    static func main() {
        let dataDir = "/tmp/reticulum-ffi-swift-test-\(ProcessInfo.processInfo.processIdentifier)"
        let fm = FileManager.default
        try? fm.removeItem(atPath: dataDir)
        try? fm.createDirectory(atPath: dataDir, withIntermediateDirectories: true)

        let app = FfiApp(dataDir: dataDir)

        let sem = DispatchSemaphore(value: 0)
        let reconciler = LifecycleReconciler(sem)
        app.listenForUpdates(reconciler: reconciler)

        app.dispatch(action: .start(transportEnabled: false))

        let result = sem.wait(timeout: .now() + .seconds(5))
        if result == .timedOut {
            print("Timed out waiting for Running state")
            exit(1)
        }

        print("Swift FFI OK: app reached Running state")
    }
}
