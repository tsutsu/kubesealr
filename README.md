# KubesealR

KubesealR is a pure-Ruby implementation of the CLI client `kubeseal` component
of Bitnami's [Kubernetes sealed-secrets](https://github.com/bitnami-labs/sealed-secrets)
system.

KubesealR also embeds a transformer plugin for [KustomizeR](https://github.com/tsutsu/kustomizer),
a pure-Ruby [Kustomize](https://kustomize.io) implementation. This plugin allows
KustomizeR to seal [generated *or* provided] secrets, as a resource-config
transformation pass.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'kubesealr'
```

And then execute:

    $ bundle install

Or install it yourself as:

    $ gem install kubesealr

## Usage

### CLI usage

(TODO; will mostly match CLI usage of `kubeseal`)

### KustomizeR Plugin usage

KubesealR provides one [Kustomize transformer plugin](https://kubectl.docs.kubernetes.io/guides/extending_kustomize/#specification-in-kustomizationyaml),
`SealSecretsTransform`, with the following K8s document-type:

```yaml
apiVersion: kubesealr.covalenthq.com/v1
kind: SealSecretsTransform
```

Possible fields on this configuration:

#### `.spec.match`

```
.spec.match: "all" | [String] | {pattern: RegexpString}
```

`.spec.match` controls which secrets will be sealed.

  * The literal string `all` will match all secrets.
  * A list of strings means "match secrets with these names exactly."
  * Setting `.spec.match.pattern` to a string will treat that string as
    a regular expression and use it to match secret names.

Defaults to `all`.

#### `.spec.keepUnsealed`

```
.spec.keepUnsealed: true | false
```

`.spec.keepUnsealed` controls whether the original, unsealed versions of
the secrets will be emitted by the transform alongside the sealed versions.
Defaults to `false`. You may want to set this to `true` if you have further
transformation passes that depend on the unsealed secrets in some way.

Add a new resource path to the `transformers` resource-list in your
`kustomization.yaml`. For example:

#### Full example Kustomize configuration

In `kustomization.yaml`:

```yaml
---
transformers:
  - seal-secrets.yaml
```


In `seal-secrets.yaml`:

```yaml
---
apiVersion: kubesealr.covalenthq.com/v1
kind: SealSecretsTransform
spec:
  match:
    pattern: "-conn$"
  keepUnsealed: false
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/tsutsu/kubesealr.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
