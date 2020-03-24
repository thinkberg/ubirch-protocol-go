# ubirch-protocol implementation for Go

This implementation used the ECDSA ECC curve also used
in our SIM card implementation.

### how to publish a version for deployment
```
go mod tidy
git tag ubirch/vx.y.z
git push origin ubirch/vx.y.z
http://github.com/ubirch/ubirch-protocol-go/ubirch/vx@vx.y.z
```
> where x.y.z is the version number