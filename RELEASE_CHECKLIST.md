# Release Checklist v0.1.0

## Pre-Release Verification
- [ ] **Tests:** Run `make test` and ensure all pass.
- [ ] **Benchmarks:** Run `make bench` and verify throughput is >900MB/s for realistic data.
- [ ] **Version:** Verify `const Version = "v0.1.0"` in `main.go`.
- [ ] **Documentation:** Ensure `README.md` benchmark numbers match current performance.

## Build Artifacts
- [ ] **Linux (amd64):**
  ```bash
  GOOS=linux GOARCH=amd64 go build -o dist/secretscalpel-linux-amd64 .
  ```
- [ ] **Linux (arm64):**
  ```bash
  GOOS=linux GOARCH=arm64 go build -o dist/secretscalpel-linux-arm64 .
  ```
- [ ] **Windows:**
  ```bash
  GOOS=windows GOARCH=amd64 go build -o dist/secretscalpel-windows-amd64.exe .
  ```
- [ ] **macOS:**
  ```bash
  GOOS=darwin GOARCH=arm64 go build -o dist/secretscalpel-darwin-arm64 .
  ```

## Docker Image
- [ ] **Build:** `docker build -t secretscalpel:v0.1.0 .`
- [ ] **Test:** `echo "password=secret" | docker run -i --rm secretscalpel:v0.1.0`
- [ ] **Tag & Push:**
  ```bash
  docker tag secretscalpel:v0.1.0 your-registry/secretscalpel:v0.1.0
  docker push your-registry/secretscalpel:v0.1.0
  ```

## Git Release
- [ ] **Tag:** `git tag v0.1.0`
- [ ] **Push:** `git push origin v0.1.0`