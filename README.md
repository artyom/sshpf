Command sshpf provides a minimalistic ssh server only allowing port
forwarding to an (optionally) limited set of addresses.

	Usage of sshpf:
	  -addr string
		address to listen (default "localhost:2022")
	  -allowed string
		file with list of allowed to connect host:port pairs
	  -auth string
		path to authorized_keys file (default "authorized_keys")
	  -hostKey string
		path to private host key file (default "id_rsa")
	  -timeout duration
		IO timeout on client connections (default 3m0s)

If `-allowed` flag left empty, no restrictions are applied. Otherwise, file is
expected to hold host:port pairs one per line; empty lines and lines starting
with # are ignored.
