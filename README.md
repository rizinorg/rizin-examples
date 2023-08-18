# Rizin Plugins Examples Repository

This repository hosts examples of how to implement Rizin plugins for each category of plugins.
Each example folder contains the necessary files to build the examples for that category.

## Building System

The building system used for these examples is meson & ninja, which makes it easy to build and install the examples on your local machine. To do this:

1. Install Meson and Ninja if you haven't already (you can follow [these instructions](https://mesonbuild.com/docs/installation/)).
2. Clone or download the repository containing the example plugins that you want to build.
3. Navigate to the cloned repository in your terminal or command prompt.
4. Run the following commands:

```sh
meson --prefix=~/.local build
ninja -C build/ install
```

These commands will compile and install the example plugins on your local machine, making them easily accessible for testing and experimentation.