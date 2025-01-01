using ToyPublicKeys
using Documenter

DocMeta.setdocmeta!(ToyPublicKeys, :DocTestSetup, :(using ToyPublicKeys); recursive=true)

makedocs(;
    modules=[ToyPublicKeys],
    authors="Jan Wagner <jenik.wagner@gmail.com> and contributors",
    sitename="ToyPublicKeys",
    format=Documenter.HTML(;
        canonical="https://NegaScout.github.io/ToyPublicKeys",
        edit_link="main",
        assets=String[],
    ),
    pages=[
        "Home" => "index.md",
    ],
)

deploydocs(;
    repo="github.com/NegaScout/ToyPublicKeys",
    devbranch="main",
)
