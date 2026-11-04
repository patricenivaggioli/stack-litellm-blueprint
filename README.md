# LiteLLM for the London Lab

This repository packages a Torque blueprint and Helm chart for a single-replica LiteLLM proxy on a London Lab OpenShift cluster. The launch form supports any combination of Mistral, OpenAI, Anthropic, and Local. Cisco AI Defense and Galileo observability are independent yes/no options.

## Files

- `blueprints/litellm.yaml`: Torque blueprint.
- `helm/litellm`: Helm chart referenced by the blueprint's `source.path`.

The blueprint uses `source.store: stack-litellm-blueprint` and `source.path: helm/litellm`. Connect this Git repository to Torque under that store name, or change `store` to its registered name. Select the Torque agent for **OCPAI-01** or **OCPAI-02** at launch. The proxy itself does not need a GPU; cluster choice matters for reaching a local model service and the external APIs.

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

Use your existing secret manager or OpenShift secret process. The London Lab note contains some credentials, but this repository contains none of their values. The note does not identify the Galileo project ID, so set `galileo_project_id` in the launch form when enabling observability.

## Options

- **AI Defense:** Cisco AI Defense is enabled on pre-call and post-call chat traffic. Flagged requests and inspection errors block by default. Set the regional API base URL in the launch form.
- **Observability:** LiteLLM's Galileo callback logs successful LLM calls to the selected Galileo Cloud project. Set `galileo_project_id`; `galileo_log_stream_id` and `galileo_base_url` are optional. Galileo logging can include model input and output, so enable it only for traffic approved for that project.
- **Local:** Choose Ollama or an OpenAI-compatible server. Set a URL reachable from the LiteLLM pod. The chart deploys only the LiteLLM proxy; it does not deploy the local model server.

The service is `ClusterIP` only. The blueprint output is an in-cluster URL. Access from outside the cluster needs a separate approved route or port-forward.

This is a lean gateway deployment. It does not provision PostgreSQL or Redis, so it does not provide persistent virtual keys, spend tracking, or multi-replica operation. For those features, use LiteLLM's production chart with managed data stores.

## Validation and launch

Run `helm lint helm/litellm` and render the options you intend to use with `helm template`. Torque server validation and launch require a configured Torque API token, a space, and a connected repository. The selected Torque agent needs permission to install Helm resources in the chosen namespace.

Sources: [Torque Helm grain](https://docs.qtorque.io/blueprint-designer-guide/blueprints/helm-grain), [LiteLLM deployment](https://docs.litellm.ai/docs/proxy/deploy), [LiteLLM Galileo callback](https://docs.litellm.ai/docs/proxy/logging).
