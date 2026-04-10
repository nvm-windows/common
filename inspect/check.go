package inspect

type Check struct {
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Problems    []Problem          `json:"problems,omitempty"`
	Warnings    []Problem          `json:"warnings,omitempty"`
	Hint        string             `json:"hint,omitempty"`
	fn          func(*Check) error `json:"-"`
}

func (c *Check) Run() error {
	if c.fn != nil {
		return c.fn(c)
	}
	return nil
}

func (c *Check) SetFn(fn func(*Check) error) {
	c.fn = fn
}

func (c *Check) Passed() bool {
	return len(c.Problems) == 0
}

type Problem struct {
	Name   string `json:"name"`
	Detail string `json:"detail,omitempty"`
	Help   string `json:"help,omitempty"`
}
