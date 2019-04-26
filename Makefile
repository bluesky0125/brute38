# detect operating system
ifeq ($(OS),Windows_NT)
    CURRENT_OS := Windows
else
    CURRENT_OS := $(shell uname -s)
endif

install:
	@go install ./cmd/hscrack
	@go install ./cmd/btcrack

build:
ifeq ($(CURRENT_OS),Windows)
	@go build  $(BUILD_FLAGS) -o ./build/hscrack.exe ./cmd/hscrack
	@go build  $(BUILD_FLAGS) -o ./build/btcrack.exe ./cmd/btcrack
else
	@go build  $(BUILD_FLAGS) -o ./build/hscrack ./cmd/hscrack
	@go build  $(BUILD_FLAGS) -o ./build/btcrack ./cmd/btcrack
endif

clean:
	@rm -rf build