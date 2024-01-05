# docker buildx bake file for local development
#
# docker buildx bake --load --pull -f bake-dev.hcl
# docker buildx bake --load --pull -f bake-dev.hcl --set '*.platform=linux/amd64'
# docker buildx bake --load --pull -f bake-dev.hcl --set '*.platform=linux/arm64'

group "default" {
  targets = ["northstar-runtime", "northstar"]
}

target "northstar-runtime" {
  context = "runtime"
  tags = ["northstar-runtime:latest"]
}

target "northstar" {
  contexts = {
    northstar-runtime = "target:northstar-runtime"
  }
  context = "northstar"
  target = "web"
  tags = ["northstar:web"]
}
