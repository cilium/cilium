package images

var ExampleImagesConf = []ImgConf{
	{
		Name: "base.img",
		Packages: []string{
			"less",
			"vim",
			"sudo",
			"openssh-server",
			"curl",
		},
		Actions: []Action{{
			Comment: "disable password for root",
			Op: &RunCommand{
				Cmd: "passwd -d root",
			},
		}},
	},
	{
		Name:   "k8s.qcow2",
		Parent: "base",
		Packages: []string{
			"docker.io",
		},
	},
}
