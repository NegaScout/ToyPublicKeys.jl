using SHA
import SHA: sha1

function SHA.sha1(data::AbstractVector)
    io = IOBuffer(data)
    return SHA.sha1(io)
end
