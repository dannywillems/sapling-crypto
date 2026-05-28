.PHONY: help
help: ## Print this help.
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; \
		{printf "  %-18s %s\n", $$1, $$2}'

.PHONY: install
install: ## Install docs dependencies.
	npm install

.PHONY: dev
dev: ## Run the docs dev server.
	npx docusaurus start

.PHONY: build
build: ## Build the static site.
	npx docusaurus build

.PHONY: preview
preview: ## Serve the built static site locally.
	npx docusaurus serve

.PHONY: clean
clean: ## Clear the Docusaurus cache.
	npx docusaurus clear

.PHONY: check-format
check-format: ## Check Markdown/MDX formatting with Prettier.
	npx prettier --check "docs/**/*.{md,mdx}"

.PHONY: format
format: ## Format Markdown/MDX with Prettier.
	npx prettier --write "docs/**/*.{md,mdx}"
