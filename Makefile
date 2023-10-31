x := "node-jwt-v$$(jq -r .version package.json).tar.gz"

archive:
	@git archive --format tar HEAD | gzip > $(x)
	@echo "Created $(x)"