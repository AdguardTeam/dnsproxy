// Package version contains dnsproxy version information.
package version

// Versions

// These are set by the linker.  Unfortunately, we cannot set constants during
// linking, and Go doesn't have a concept of immutable variables, so to be
// thorough we have to only export them through getters.
var (
	branch     string
	committime string
	revision   string
	version    string
)

// Branch returns the compiled-in value of the Git branch.
func Branch() (b string) {
	return branch
}

// CommitTime returns the compiled-in value of the build time as a string.
func CommitTime() (t string) {
	return committime
}

// Revision returns the compiled-in value of the Git revision.
func Revision() (r string) {
	return revision
}

// Version returns the compiled-in value of the build version as a string.
func Version() (v string) {
	return version
}
