//go:build race

package stream

// raceEnabled is true when tests run with -race, which makes them several
// times slower; long-running tests use smaller inputs then.
const raceEnabled = true
