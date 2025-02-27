package main

import (
	"github.com/alecthomas/kong"
	"github.com/califio/code-secure-analyzer"
	"github.com/califio/code-secure-analyzer/logger"
	"trivy/trivy"
)

type DependencyCmd struct {
	SkipDbUpdate bool   `help:"Skip DB update" env:"TRIVY_SKIP_DB_UPDATE" default:"false"`
	ProjectPath  string `help:"Project path" env:"PROJECT_PATH" default:"."`
}

func (r *DependencyCmd) Run() error {
	dependencyAnalyzer := analyzer.NewSCAAnalyzer()
	dependencyAnalyzer.RegisterScanner(&trivy.DependencyScanner{
		SkipDbUpdate: r.SkipDbUpdate,
		ProjectPath:  r.ProjectPath,
	})
	dependencyAnalyzer.Run()
	return nil
}

type ContainerCmd struct {
	Image string `env:"DOCKER_IMAGE" name:"image" help:"docker image" type:"string"`
}

func (r *ContainerCmd) Run() error {
	logger.Info("coming soon")
	return nil
}

var cli struct {
	Dependency DependencyCmd `cmd:"" help:"Scan dependency project"`
	Container  ContainerCmd  `cmd:"" help:"Scan container"`
}

func main() {
	ctx := kong.Parse(&cli, kong.Name("analyzer"), kong.UsageOnError())
	err := ctx.Run()
	ctx.FatalIfErrorf(err)
}
