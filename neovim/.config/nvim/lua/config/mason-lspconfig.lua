require("mason-lspconfig").setup {
	-- ensure_installed = { "lua_ls","java_language_server" }
	ensure_installed = { "lua_ls", "tsserver", "pyright" }
}
