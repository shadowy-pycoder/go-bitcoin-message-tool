APP_NAME?=bmt
TEST_DIR?=./${APP_NAME}

build: 
	go build  -o ./bin/ ./cmd/${APP_NAME}/

bench:
	go test -o ${TEST_DIR} ${TEST_DIR} -bench=. -run=^$$ -benchtime 10000x -cpuprofile='${TEST_DIR}/cpu.prof' -memprofile='${TEST_DIR}/mem.prof'

test:
	go test -o ${TEST_DIR} -v -count=1 ${TEST_DIR}

test100:
	go test -o ${TEST_DIR} -v -count=100 ${TEST_DIR}

race:
	go test -o ${TEST_DIR} -v -race -count=1 ${TEST_DIR}

.PHONY: cover
cover:
	go test -o ${TEST_DIR} -short -count=1 -race -coverprofile=coverage.out ${TEST_DIR}
	go tool cover -html=coverage.out
	rm coverage.out