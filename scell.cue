_gh_token: string

main: {
	from_image: "debian:trixie"
	env: [
		// claude, pixi code instalation path
		"PATH=\"/root/.pixi/bin:/root/.local/bin:$PATH\"",
		"GH_TOKEN=\"\(_gh_token)\""
	]
	build: [
		"apt-get update --fix-missing",
		"apt-get -y install git curl wget",
		// install pixi
		"curl -fsSL https://pixi.sh/install.sh | sh",
		// claude code
		"curl -fsSL https://claude.ai/install.sh | bash",
		// install Github Cli
		"apt install -y gh",
		// zsh
		"apt install -y zsh",
	]
	workspace: "mojo-crypto"
	shell:     "/bin/zsh"
	hang:      "while true; do sleep 3600; done"
	config: {
		mounts: [
			"./:/mojo-crypto/",
		]
	}
}
