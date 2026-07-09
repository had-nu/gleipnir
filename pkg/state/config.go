package state

type Config struct {
	Eta        float64
	DecayRate  float64
	MinLambda1 float64
}

var DefaultConfig = Config{
	Eta:        0.28,
	DecayRate:  0.05,
	MinLambda1: 0.10,
}
