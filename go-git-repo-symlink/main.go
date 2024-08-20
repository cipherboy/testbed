package main

import (
	"fmt"
	"os"

	"github.com/go-git/go-billy/v5/osfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

func getRepo(dir string) (*git.Repository, error) {
	// See https://github.com/go-git/go-git/issues/1155#issuecomment-2242778023
	wt := osfs.New(dir, osfs.WithBoundOS())
	dotfs, err := wt.Chroot(git.GitDirName)
	if err != nil {
		return nil, err
	}
	store := filesystem.NewStorage(dotfs, cache.NewObjectLRUDefault())

	// Clone -> Open
	return git.Open(store, wt)
}

func walkCommits(repo *git.Repository) error {
	iter, err := repo.CommitObjects()
	if err != nil {
		return fmt.Errorf("failed getting commit objects: %v", err)
	}

	repoW, err := repo.Worktree()
	if err != nil {
		return fmt.Errorf("failed to get repo worktree: %v", err)
	}

	if err := iter.ForEach(func(commit *object.Commit) error {
		if err := repoW.Checkout(&git.CheckoutOptions{Hash: commit.Hash, Force: true}); err != nil {
			return fmt.Errorf("failed to checkout commit (%#v): %v", commit.Hash.String(), err)
		}

		return nil
	}); err != nil {
		return fmt.Errorf("failed iterating over commit object: %v", err)
	}

	return nil
}

func main() {
	dir := "repos/example"
	if len(os.Args) > 1 {
		dir = os.Args[1]
	}

	fmt.Printf("using dir=%v\n", dir)

	repo, err := getRepo(dir)
	if err != nil {
		panic(fmt.Sprintf("failed getting repository: %v", err))
	}

	if err := walkCommits(repo); err != nil {
		panic(fmt.Sprintf("failed walking commits: %v", err))
	}
}
