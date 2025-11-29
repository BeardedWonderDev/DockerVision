import Foundation

public struct DockerVisionConfig {
    public var baseURL: URL
    public var token: String?

    public init(baseURL: URL, token: String? = nil) {
        self.baseURL = baseURL
        self.token = token
    }
}

public final class DockerVisionClient {
    private let config: DockerVisionConfig
    private let session: URLSession

    public init(config: DockerVisionConfig, session: URLSession = .shared) {
        self.config = config
        self.session = session
    }

    // MARK: REST

    public func listContainers() async throws -> [ContainerSummary] {
        try await request(path: "/containers", decode: ContainersResponse.self).containers
    }

    public func systemInfo() async throws -> SystemInfo {
        try await request(path: "/system/info", decode: SystemInfo.self)
    }

    public func control(id: String, action: String) async throws {
        _ = try await request(path: "/containers/\(id)/\(action)", method: "POST", decode: Empty.self)
    }

    public func logs(id: String, tail: Int = 100) async throws -> String {
        let data = try await dataRequest(path: "/containers/\(id)/logs?lines=\(tail)&stdout=true&stderr=true")
        return String(data: data, encoding: .utf8) ?? ""
    }

    // MARK: WebSocket (events/logs/exec)

    public func connectWebSocket(path: String = "/ws") async throws -> URLSessionWebSocketTask {
        var url = config.baseURL
        url.append(path: path)
        var request = URLRequest(url: url)
        if let token = config.token {
            request.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let task = session.webSocketTask(with: request)
        task.resume()
        return task
    }

    // MARK: - Helpers

    private func request<T: Decodable>(path: String, method: String = "GET", decode: T.Type) async throws -> T {
        let data = try await dataRequest(path: path, method: method)
        return try JSONDecoder().decode(T.self, from: data)
    }

    private func dataRequest(path: String, method: String = "GET") async throws -> Data {
        var url = config.baseURL
        url.append(path: path)
        var req = URLRequest(url: url)
        req.httpMethod = method
        if let token = config.token {
            req.addValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }
        let (data, resp) = try await session.data(for: req)
        guard let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) else {
            throw DockerVisionError.httpError((resp as? HTTPURLResponse)?.statusCode ?? -1)
        }
        return data
    }
}

// MARK: Models

public struct ContainersResponse: Decodable {
    public let containers: [ContainerSummary]
}

public struct ContainerSummary: Decodable, Identifiable {
    public let id: String
    public let name: String
    public let image: String
    public let state: String
    public let status: String
}

public struct SystemInfo: Decodable {
    public let serverVersion: String
    public let operatingSystem: String
    public let osType: String
    public let architecture: String
    public let kernelVersion: String
    public let nCPU: Int
    public let memTotal: UInt64
}

public enum DockerVisionError: Error {
    case httpError(Int)
}

public struct Empty: Decodable {}
