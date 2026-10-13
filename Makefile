# gomount — read, pull and FUSE-mount disk-image volumes, CGO off.
#
# The standard Go target set (go-standards.md §13): build test vet fmt
# fmt-check tidy generate conform upgrade, plus lint structlint vuln
# (build-and-test.md §2.2). `make conform` is the gate CI runs
# (scripts/go-conform.sh); fmt writes, fmt-check gates.
GO ?= go

# the one command this module builds
BINARY   ?= gomount
MAIN_PKG ?= .

# ---- gate knobs, read by scripts/go-conform.sh --------------------------------
# extra `go vet` flags
VET_FLAGS ?=
# `go test` flags (build-and-test.md §3.2)
TEST_FLAGS ?= -count=1 -shuffle=on -cover
# build-tag sets that must also vet, build and test (go-standards.md §9)
BUILD_TAGS ?=
# GOOS/GOARCH pairs the module must cross-compile for, CGO_ENABLED=0
CROSS_TARGETS ?= 
export VET_FLAGS TEST_FLAGS BUILD_TAGS CROSS_TARGETS

.PHONY: build test vet fmt fmt-check tidy generate conform lint structlint vuln upgrade clean

build: ## build every package, then the command (static, CGO off)
	$(GO) build ./...
	CGO_ENABLED=0 $(GO) build -o $(BINARY) $(MAIN_PKG)

test: ## the tests, exactly as the gate runs them
	$(GO) test $(TEST_FLAGS) ./...

vet:
	$(GO) vet $(VET_FLAGS) ./...

fmt: ## gofmt -w the tracked Go files (writes)
	@git ls-files -z -- '*.go' | xargs -0 -r gofmt -w

fmt-check: ## fail if any tracked Go file needs gofmt (gates)
	@out=$$(git ls-files -z -- '*.go' | xargs -0 -r gofmt -l); if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

tidy:
	$(GO) mod tidy

generate:
	$(GO) generate ./...

conform: ## the gate (go-standards.md §12): gofmt, vet, build, test, tidy, tags, cross-compile, generate drift, structlint
	@scripts/go-conform.sh

structlint: ## the structural lint and the must-have files (go-standards.md §1–§3, §6, §7, §11, §13)
	@scripts/structlint.sh

lint: ## golangci-lint with .golangci.yml — install the version .github/workflows/ci.yml pins
	@command -v golangci-lint >/dev/null 2>&1 || { echo "golangci-lint is not installed: see https://golangci-lint.run/docs/welcome/install/ (CI pins $$(sed -n 's/^ *GOLANGCI_LINT_VERSION: *//p' .github/workflows/ci.yml))"; exit 1; }
	golangci-lint config verify
	golangci-lint run ./...

vuln: ## govulncheck against the current database (build-and-test.md §3.2, §8)
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

upgrade: ## raise the go directive and every dependency to the highest allowed, then conform (go-standards.md §12)
	@scripts/go-upgrade.sh

clean:
	rm -f $(BINARY)
