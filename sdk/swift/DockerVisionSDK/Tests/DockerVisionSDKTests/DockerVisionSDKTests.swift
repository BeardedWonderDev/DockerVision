import XCTest
@testable import DockerVisionSDK

final class DockerVisionSDKTests: XCTestCase {
    func testConfigInit() {
        let url = URL(string: "http://localhost:8364")!
        let cfg = DockerVisionConfig(baseURL: url, token: "t")
        XCTAssertEqual(cfg.baseURL, url)
        XCTAssertEqual(cfg.token, "t")
    }
}
