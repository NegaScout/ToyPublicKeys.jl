using ToyPublicKeys
using Documenter

DocMeta.setdocmeta!(ToyPublicKeys, :DocTestSetup, :(using ToyPublicKeys); recursive=true)

makedocs(;
    modules=[ToyPublicKeys],
    authors="Jan Wagner <jenik.wagner@gmail.com> and contributors",
    sitename="ToyPublicKeys",
    format=Documenter.HTML(;
        canonical="https://NegaScout.github.io/ToyPublicKeys.jl",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
        "Examples" => "examples.md",
        "API Reference" => "api_reference.md",
    ],
)

deploydocs(;
    repo="github.com/NegaScout/ToyPublicKeys.jl",
    devbranch="main",
)
