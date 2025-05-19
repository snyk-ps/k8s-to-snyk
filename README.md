![snyk-oss-category](https://github.com/snyk-labs/oss-images/blob/main/oss-community.jpg)

# K8s to Snyk

`k8s-to-snyk` is a Python script that fetches container image names from a Kubernetes cluster and then maps them to orgs in Snyk. It then outputs the mapped images to a JSON file suitable for importing into Snyk via the [Snyk API import tool](https://github.com/snyk/snyk-api-import).

## Features

- Fetches container images from Kubernetes pods across specified namespaces or all namespaces.
- Filters images using a regex exclude pattern.
- Maps images to Snyk organizations and integrations based on pod labels or namespaces, as configured in the configuration file.
- Outputs the mapped images to a JSON targets file use for Snyk API Import Tool.
- Supports custom Kubernetes configuration files.

## Prerequisites

- Python 3.8+
- `kubectl` configured to access your Kubernetes cluster.
- `kubernetes` Python library (https://pypi.org/project/kubernetes/).
- `PyYAML` Python library (https://pypi.org/project/PyYAML/).
- `snyk-api-import`
  https://github.com/snyk/snyk-api-import
- Container registry integration configured in Snyk.
  https://docs.snyk.io/scan-with-snyk/snyk-container/container-registry-integrations

## Installation

1.  Clone the repository:

    ```bash
    git clone https://github.com/snyk-ps/k8s-to-snyk.git
    cd kubectl-images
    ```

2.  Install the required Python packages:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

Create a configuration file (e.g., `config.yaml`) to specify namespaces, image filters, and Snyk mappings. Sample below:

```yaml
namespaces:
  - default
  - production
image_filter_regex_exclude: ".*-debug.*"
snyk_org_mapping:
  default:
    snyk_integration_id: <snyk_integration_id>
    snyk_org_id: <snyk_org_id>
  map_on: "image_label" # 'image_label', 'image_name', or "namespace"
  image_label: "app" # if map_on is 'image_label'
  org_name_values:
    snyk_org_name_1:
      snyk_integration_id: <snyk_integration_id_1>
      snyk_org_id: <snyk_org_id_1>
    snyk_org_name_2:
      snyk_integration_id: <snyk_integration_id_2>
      snyk_org_id: <snyk_org_id_2>
targets_file_output_path: "./imported-targets.json"
```

- `namespaces`: Optional: A list of Kubernetes namespaces to scan. If not provided, all namespaces are scanned.
- `image_filter_regex_exclude`: Optional: A regex pattern to exclude images.
- `snyk_org_mapping`: Required: Configuration for mapping images to Snyk.
  - `default`: Optional: Configuration for mapping to a default org in Snyk in cases where no mapping exists for an image.
    - `snyk_integration_id`: Optional: Container registry integration ID of the default Snyk orginization.
    - `snyk_org_id`: Optional: Org ID of the the default Snyk orginization
  - `map_on`: Required: Specifies the mapping method ("image_label", "image_name", or "namespace").
  - `mapping_value_pattern`: Optional: Use regex to extract substring from mapping value.
  - `image_label`: The label name to use for mapping (Required if `map_on` is "image_label").
  - `values`: Required: A dictionary mapping label values or namespaces to Snyk organization and integration IDs.
- `targets_file_output_path`: Optional: The path to the output the targets file. Default is ./imported-targets.json

## Usage

Run the script with the following command:

```bash
python kubectl_images.py --config config.yaml --kube-config ~/.kube/config
```

- `--config`: Path to the configuration file (default: `config.yaml`).
- `--kube-config`: Path to the Kubernetes configuration file. If not provided, the default Kubernetes configuration is used.

## Output

The script generates a JSON file (e.g., `imported-targets.json`) containing the mapped images in a format suitable for the Snyk API import tool. Sample below:

```json
{
  "targets": [
    {
      "orgId": "your-org-id-1",
      "integrationId": "your-integration-id-1",
      "target": {
        "name": "image1:latest"
      }
    },
    {
      "orgId": "your-org-id-2",
      "integrationId": "your-integration-id-2",
      "target": {
        "name": "image2:latest"
      }
    }
  ]
}
```

## Logging

The script uses the Python `logging` module to provide detailed logs. Logs are written to the console and include timestamps and log levels.

## Error Handling

The script includes error handling for:

- Loading Kubernetes configuration.
- Reading and parsing configuration files.
- Fetching pod information.
- Filtering images using regex.
- Writing output to target file.

## Contributing

Contributions are welcome! Please submit a pull request or create an issue to report bugs or suggest enhancements.
