// A module of its own, so the vector generator can depend on colbin without
// joining the backend's module graph.
module github.com/ivanjoz/fareward/vectors

go 1.27

require (
	github.com/ivanjoz/colbin v0.3.0
	github.com/ivanjoz/fareward/go v0.0.0
	golang.org/x/crypto v0.56.0
)

// The siphash package the vectors are keyed with lives in the client module beside this one, so
// the generated hashes come from the same code the backend and the daemon's Go client run.
replace github.com/ivanjoz/fareward/go => ../go

require golang.org/x/sys v0.47.0 // indirect
