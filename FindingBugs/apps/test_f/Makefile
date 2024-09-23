.DEFAULT_GOAL=help
.PHONY: run build clean help
TARGET = test_a


run: ## Run the test case

build: ## Build the test case
	mvn package

clean: ## Clean the test case
	mvn clean

help: ## Show this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
