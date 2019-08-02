go-rate
===============

[![Build Status](https://travis-ci.org/beefsack/go-rate.svg?branch=master)](https://travis-ci.org/beefsack/go-rate)
[![GoDoc](https://godoc.org/github.com/beefsack/go-rate?status.svg)](https://godoc.org/github.com/beefsack/go-rate)

**go-rate** is a rate limiter designed for a range of use cases,
including server side spam protection and preventing saturation of APIs you
consume.

It is used in production at
[LangTrend](http://langtrend.com/l/Java,PHP,JavaScript) to adhere to the GitHub
API rate limits.

Usage
-----

Import `github.com/beefsack/go-rate` and create a new rate limiter with
the `rate.New(limit int, interval time.Duration)` function.

The rate limiter provides a `Wait()` and a `Try() (bool, time.Duration)` method
for both blocking and non-blocking functionality respectively.

API documentation available at [godoc.org](http://godoc.org/github.com/beefsack/go-rate).

Examples
--------

### Blocking rate limiting

This example demonstrates limiting the output rate to 3 times per second.

```Go
package main

import (
	"fmt"
	"time"

	"github.com/beefsack/go-rate"
)

func main() {
	rl := rate.New(3, time.Second) // 3 times per second
	begin := time.Now()
	for i := 1; i <= 10; i++ {
		rl.Wait()
		fmt.Printf("%d started at %s\n", i, time.Now().Sub(begin))
	}
	// Output:
	// 1 started at 12.584us
	// 2 started at 40.13us
	// 3 started at 44.92us
	// 4 started at 1.000125362s
	// 5 started at 1.000143066s
	// 6 started at 1.000144707s
	// 7 started at 2.000224641s
	// 8 started at 2.000240751s
	// 9 started at 2.00024244s
	// 10 started at 3.000314332s
}
```

### Blocking rate limiting with multiple limiters

This example demonstrates combining rate limiters, one limiting at once per
second, the other limiting at 2 times per 3 seconds.

```Go
package main

import (
	"fmt"
	"time"

	"github.com/beefsack/go-rate"
)

func main() {
	begin := time.Now()
	rl1 := rate.New(1, time.Second)   // Once per second
	rl2 := rate.New(2, time.Second*3) // 2 times per 3 seconds
	for i := 1; i <= 10; i++ {
		rl1.Wait()
		rl2.Wait()
		fmt.Printf("%d started at %s\n", i, time.Now().Sub(begin))
	}
	// Output:
	// 1 started at 11.197us
	// 2 started at 1.00011941s
	// 3 started at 3.000105858s
	// 4 started at 4.000210639s
	// 5 started at 6.000189578s
	// 6 started at 7.000289992s
	// 7 started at 9.000289942s
	// 8 started at 10.00038286s
	// 9 started at 12.000386821s
	// 10 started at 13.000465465s
}
```

### Non-blocking rate limiting

This example demonstrates non-blocking rate limiting, such as would be used to
limit spam in a chat client.

```Go
package main

import (
	"fmt"
	"time"

	"github.com/beefsack/go-rate"
)

var rl = rate.New(3, time.Second) // 3 times per second

func say(message string) {
	if ok, remaining := rl.Try(); ok {
		fmt.Printf("You said: %s\n", message)
	} else {
		fmt.Printf("Spam filter triggered, please wait %s\n", remaining)
	}
}

func main() {
	for i := 1; i <= 5; i++ {
		say(fmt.Sprintf("Message %d", i))
	}
	time.Sleep(time.Second / 2)
	say("I waited half a second, is that enough?")
	time.Sleep(time.Second / 2)
	say("Okay, I waited a second.")
	// Output:
	// You said: Message 1
	// You said: Message 2
	// You said: Message 3
	// Spam filter triggered, please wait 999.980816ms
	// Spam filter triggered, please wait 999.976704ms
	// Spam filter triggered, please wait 499.844795ms
	// You said: Okay, I waited a second.
}
```

Authors
-------

* [Michael Alexander](https://github.com/beefsack)
* [Geert-Johan Riemer](https://github.com/GeertJohan)
* [Matt T. Proud](https://github.com/matttproud)
