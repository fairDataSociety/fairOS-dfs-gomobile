# fairOS-dfs-gomobile

fairos is built in a way that is supports gomobile and can be used as android or ios package.
It can also work standalone with any go codebase. It is not a backend solution, 
for that we should use [fairOS-dfs](https://github.com/fairDataSociety/fairOS-dfs). 
It is more of a frontend solution to be used in cli, desktop or mobile apps where only one user will interact with fairOS.

This package creates a global `dfs.API` instance, then saves user password in that instance after a successful login and will function for that user only.

### How to build for android (aar for android)?
```
$ go mod tidy
$ go get golang.org/x/mobile
$ go generate
```

### How to build for ios?
```
Coming soon
```

### How to use in go codebase?
```
Coming soon
```

### How to use in android?
Check out this [demo](https://github.com/fairDataSociety/fairOS-dfs-android-demo)

*** The code is not fully tested. Please use [fairOS-dfs](https://github.com/fairDataSociety/fairOS-dfs) for a better experience.


