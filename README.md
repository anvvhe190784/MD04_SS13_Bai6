# Session 13: Xây dựng hệ thống xác thực Microservices với JWT

Hệ thống Microservices hoàn chỉnh bao gồm:
- `identity-service` (cổng 8080): Quản lý người dùng, băm mật khẩu BCrypt, cấp phát và xác thực JWT.
- `gateway-service` (cổng 8888): API Gateway (Spring Cloud Gateway WebFlux) định tuyến, chặn bắt và validate JWT, trích xuất Claims và chuyển tiếp User Context.
- `product-service` (cổng 8081): Dịch vụ đích tiếp nhận request và phân quyền dựa trên User Context (`X-User-Role`).

---

## [Bài tập 1] Khởi tạo Identity Service và Bảo mật mật khẩu
- Quản lý entity `User` (id: UUID, username, password, role).
- Băm mật khẩu an toàn với `BCryptPasswordEncoder`.
- Cấu hình Spring Security tắt CSRF và cho phép truy cập công khai endpoint đăng ký.
- API: `POST /api/auth/register` tiếp nhận thông tin người dùng và lưu vào database PostgreSQL `identity_db`.

---

## [Bài tập 2] Xây dựng bộ công cụ cấp phát JSON Web Token (JWT)
- Tích hợp thư viện `io.jsonwebtoken:jjwt-api:0.11.5`.
- Cấu hình secret 256-bit và expiration 3600000ms trong `application.yml`.
- `JwtUtil`: Sinh token với Claims `sub` (username), custom claim `role`, ký HMAC-SHA256.
- API: `GET /api/auth/test-token?username={name}` tìm người dùng trong DB và cấp token.
- Kiểm tra tính hợp lệ của Payload trên [jwt.io](https://jwt.io).

---

## [Bài tập 3] Triển khai Stateless Authentication Flow với Spring Security
- Cấu hình `SessionCreationPolicy.STATELESS` (vô hiệu hóa HttpSession và cookie JSESSIONID).
- Đăng ký `BCryptPasswordEncoder` bean để Spring Security so khớp mật khẩu qua `passwordEncoder.matches()`.
- API: `POST /api/auth/login` tiếp nhận `LoginRequest` (username, password):
  - Thành công: Trả về HTTP 200 kèm JWT access token.
  - Thất bại: Trả về HTTP 401 Unauthorized kèm thông điệp chung `Bad credentials` để bảo mật.
- Kiểm thử toàn diện qua JUnit 5 Mockito cho các kịch bản thành công và thất bại.

---

## [Bài tập 4] Cấu hình Routing tại API Gateway
- Khởi tạo dự án `gateway-service` (Spring Boot Java 21, Spring Cloud Gateway WebFlux/Netty cổng 8888, không sử dụng `spring-boot-starter-web`).
- Cấu hình Route Predicates & Filters trong `application.yml`:
  - Route `/identity/**` trỏ về `http://localhost:8080`.
  - Filter `StripPrefix=1` loại bỏ tiền tố `/identity` trước khi chuyển tiếp request tới `identity-service`.
  - Route mô phỏng `/api/products/**` trỏ về `http://localhost:8081`.
- Kiểm thử:
  - `POST http://localhost:8888/identity/api/auth/login` -> chuyển tiếp thành công đến `identity-service:8080/api/auth/login`.
  - Gọi sai tiền tố `/wrong-path/**` -> Gateway trả về HTTP 404 Not Found.

---

## [Bài tập 5] Chặn bắt và Validate JWT tại API Gateway
- Triển khai `GlobalFilter` (`JwtAuthenticationFilter`) tại `gateway-service`:
  - Cho phép truy cập không cần token đối với các API Auth (`/identity/api/auth/**`, `/api/auth/**`).
  - Chặn bắt Header `Authorization: Bearer <token>`.
  - Giải mã và kiểm tra tính hợp lệ của JWT (sai chữ ký, hết hạn, thiếu token).
  - Trả về mã lỗi HTTP 401 Unauthorized dưới dạng JSON chuẩn, không gây crash Gateway.

---

## [Bài tập 6] Trích xuất Claims và chuyển tiếp User Context
- Tại `gateway-service`:
  - Sau khi validate token thành công, trích xuất `sub` (username) và `role` từ claims.
  - Mutate request thêm 2 headers tùy chỉnh: `X-User-Id` và `X-User-Role` trước khi forward sang dịch vụ đích.
- Tại `product-service` (cổng 8081):
  - Triển khai endpoint `POST /api/products` và `GET /api/products`.
  - Đọc header `@RequestHeader("X-User-Role")`:
    - Nếu role là `ADMIN`: Cho phép xử lý -> Trả về HTTP 200 OK.
    - Nếu role là `USER` hoặc khác: Từ chối truy cập -> Trả về HTTP 403 Forbidden.
- Kiểm thử luồng phân quyền end-to-end:
  - Gọi qua Gateway với Token của `USER` -> Nhận HTTP 403 Forbidden.
  - Gọi qua Gateway với Token của `ADMIN` -> Nhận HTTP 200 OK.
