# LiteLLM for the London Lab

This repository packages a Torque blueprint and Helm chart for a single-replica LiteLLM proxy on London Lab OCPAI-02. The AI-Services launch form supports any combination of Mistral, OpenAI, Anthropic, and Local. Cisco AI Defense and Galileo observability are independent yes/no options.

## Files

- `blueprints/litellm.yaml`: Torque blueprint.
- `helm/litellm`: Helm chart referenced by the blueprint's `source.path`.
- `scripts/get-route-url.sh`: Reads the admitted OpenShift Route host for the Torque output.

The blueprint uses `source.store: stack-litellm-blueprint` and `source.path: helm/litellm`. Connect this Git repository to Torque under that store name, or change `store` to its registered name. Select the Torque agent for **OCPAI-02** at launch. The proxy itself does not need a GPU; cluster choice matters for reaching a local model service and the external APIs.

The chart uses the pinned `ghcr.io/berriai/litellm-non_root:v1.108.0` image and a restricted container security context for OpenShift. The target namespace must contain the Secret below before launch. The Helm grain has `--create-namespace`, but create the namespace first if you need to create the Secret there.

## Credentials

Create a Kubernetes Secret in the target namespace before launching. Its default name is `litellm-credentials`; the `credentials_secret` input can select another existing name. Keep values out of Git. Provide these keys only as needed:

| Secret key | When needed |
| --- | --- |
| `LITELLM_MASTER_KEY` | Always; choose a strong `sk-` prefixed value. |
| `OPENAI_API_KEY` | OpenAI selected. |
| `MISTRAL_API_KEY` | Mistral selected. |
| `ANTHROPIC_API_KEY` | Anthropic selected. |
| `LOCAL_API_KEY` | OpenAI-compatible local server; use a non-secret placeholder value if the server does not require authentication. |
| `CISCO_AI_DEFENSE_API_KEY` | AI Defense enabled. |
| `GALILEO_API_KEY` | Observability enabled. |

Use your existing secret manager or OpenShift secret process. The London Lab note contains some credentials, but this repository contains none of their values. The `litellm` namespace on OCPAI-02 already has the required keys for the default Mistral, AI Defense, and Galileo choices. Create a Secret in any other namespace before launching there.

## Options

- **AI Defense:** Enabled by default. Cisco AI Defense inspects chat traffic before and after the model call. Flagged requests and inspection errors block. The API key must belong to a connection with an enabled runtime policy; the proxy cannot supply that policy.
- **Observability:** Enabled by default. LiteLLM's Galileo success callback logs LLM calls to the existing **liteLLM gateway** project (`c31f19d9-d20d-44f8-bd8b-3c361f71db7b`) and **litellm-requests** stream (`ffc69b3a-b792-4907-b331-64ddf162af5d`). Override either ID in the launch form for another destination. Galileo logging can include model input and output, so use an approved project.
- **Local:** Choose Ollama or an OpenAI-compatible server. Set a URL reachable from the LiteLLM pod. The chart deploys only the LiteLLM proxy; it does not deploy the local model server.

The chart creates an OpenShift Route for each release with edge TLS and HTTP-to-HTTPS redirect. OpenShift assigns a unique host; the blueprint reports the admitted `route_url` as a clickable output. The in-cluster `service_url` remains available for workloads inside OCPAI-02. The Route is Helm-managed and is removed with its release.

The existing `QhCEY6FCKUby` environment has a Route created before this chart version. Adopt or remove that manual Route before upgrading that same Helm release to chart `0.2.0`; new environments create their own Helm-managed Routes automatically.

This is a lean gateway deployment. It does not provision PostgreSQL or Redis, so it does not provide persistent virtual keys, spend tracking, or multi-replica operation. For those features, use LiteLLM's production chart with managed data stores.

## Validation and launch

Run `helm lint helm/litellm` and render the options you intend to use with `helm template`. Torque server validation and launch require a configured Torque API token, a space, and a connected repository. The selected Torque agent needs permission to create OpenShift Routes and run the post-install Route lookup in the chosen namespace.

Sources: [Torque Helm grain](https://docs.qtorque.io/blueprint-designer-guide/blueprints/helm-grain), [LiteLLM deployment](https://docs.litellm.ai/docs/proxy/deploy), [LiteLLM Galileo callback](https://docs.litellm.ai/docs/proxy/logging).
