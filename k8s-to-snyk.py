import logging
import json
import re
from kubernetes import client, config
import yaml
import argparse

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("k8s-to-snyk")


class Client:
    def __init__(self, kube_config=None, config_file="config.yaml"):
        """Initializes the Client and loads the Kubernetes configuration and configuration file."""
        self.api = self._load_kube_config(kube_config)
        self.config_data = self._load_config_file(config_file)

    def _load_config_file(self, config_file):
        """Loads configuration data from a JSON or YAML file."""
        try:
            with open(config_file, "r") as f:
                if config_file.endswith(".json"):
                    return json.load(f)
                elif config_file.endswith(".yaml") or config_file.endswith(".yml"):
                    return yaml.safe_load(f)
                else:
                    logger.error(
                        "Unsupported config file format. Must be JSON or YAML."
                    )
                    return {}
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_file}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding JSON config file: {e}")
            return {}
        except yaml.YAMLError as e:
            logger.error(f"Error decoding YAML config file: {e}")
            return {}

    def _load_kube_config(self, kube_config):
        try:
            logger.info("Loading Kubernetes configuration...")
            if kube_config:
                logger.info(f"Using provided kube config file: {kube_config}")
                config.load_kube_config(config_file=kube_config)
            else:
                config.load_kube_config()
            api = client.CoreV1Api()
            logger.info("Kubernetes configuration loaded successfully.")
            return api
        except config.config_exception.ConfigException as e:
            logger.error(f"Error loading Kubernetes configuration: {e}")
            raise

    def _get_image_metadata_from_pods(self, pods):
        """Fetches image metadata (image name and mapping label value) for a pod"""
        try:
            images = {}
            mapping = self.config_data.get("snyk_org_mapping")
            mapping_label = ""
            if mapping.get("map_on") == "label":
                mapping_label = mapping.get("label")

            for pod in pods.items:
                label_value = ""
                if mapping_label:
                    labels = pod.metadata.labels
                    label_value = labels.get(mapping_label)

                for container in pod.spec.containers:
                    image_name = container.image
                    images[image_name] = {"namespace": pod.metadata.namespace}
                    images[image_name].update({"label": label_value})

                if pod.spec.init_containers:
                    for init_container in pod.spec.init_containers:
                        image_name = init_container.image
                        images[image_name] = {"namespace": pod.metadata.namespace}
                        images[image_name].update({"label": label_value})
            return images

        except client.exceptions.ApiException as e:
            logger.error(f"Error fetching pod information: {e}")
            return None
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {e}")
            return None

    def get_all_image_metadata(self, namespaces=None):
        """Fetches all image names and labels across specified namespaces or all if none are provided."""
        try:
            images = {}
            if namespaces:
                for namespace in namespaces:
                    pods = self.api.list_namespaced_pod(
                        namespace=namespace, watch=False
                    )
                    pod_images = self._get_image_metadata_from_pods(pods)
                    images.update(pod_images)
            else:
                pods = self.api.list_pod_for_all_namespaces(watch=False)
                pod_images = self._get_image_metadata_from_pods(pods)
                images.update(pod_images)
            return images
        except Exception as e:
            logger.exception(f"Error getting image metadata: {e}")
            return None

    def filter_images(self, images, exclude_regex):
        """Filters out images based on a regex pattern."""
        if not exclude_regex:
            return images
        try:
            filtered_images = [
                image for image in images if not re.search(exclude_regex, image)
            ]
            return filtered_images
        except re.error as e:
            logger.error(f"Invalid regex pattern: {e}")
            return images

    def map_image_to_snyk(self, image):
        """Maps an image to Snyk org and integration ID based on config."""
        image_name = image[0]
        snyk_mapping = self.config_data.get("snyk_org_mapping", {})
        if not snyk_mapping:
            return None

        snyk_data = None
        map_on = snyk_mapping.get("map_on")
        if map_on == "label":
            label_value = image[1].get("label")
            snyk_data = snyk_mapping.get("values").get(label_value)

        elif map_on == "namespace":
            namespace_value = image[1].get("namespace")
            snyk_data = snyk_mapping.get("values").get(namespace_value)

        if snyk_data:
            return {
                "image": image_name,
                "orgId": snyk_data.get("snyk_org_id"),
                "integrationId": snyk_data.get("snyk_integration_id"),
            }

        else:
            default = snyk_mapping.get("default")
            if default:
                default_mapping = {
                    "image": image_name,
                    "orgId": default.get("snyk_org_id"),
                    "integrationId": default.get("snyk_integration_id"),
                }
                return default_mapping
            else:
                return None

    def create_targets_file(self, images_data, output_file="imported-targets.json"):
        """Generates targets file for use by API Import Tool"""
        targets = []
        for image_data in images_data:
            image_path = image_data["image"].split("/")
            target = f"{image_path[-2]}/{image_path[-1]}"
            targets.append(
                {
                    "orgId": image_data["orgId"],
                    "integrationId": image_data["integrationId"],
                    "target": {"name": target},
                }
            )
        output_data = {"targets": targets}
        try:
            with open(output_file, "w") as f:
                json.dump(output_data, f, indent=2)
            logger.info(f"Output written to {output_file}")
        except Exception as e:
            logger.error(f"Error writing to JSON file: {e}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Fetch container images from Kubernetes and map them to Snyk."
    )
    parser.add_argument(
        "--kube-config", help="Path to the Kubernetes configuration file."
    )
    parser.add_argument(
        "--config", default="config.yaml", help="Path to the configuration file."
    )
    args = parser.parse_args()

    try:
        client = Client(kube_config=args.kube_config, config_file=args.config)

        namespaces_to_scan = client.config_data.get("namespaces")
        all_images = client.get_all_image_metadata(namespaces=namespaces_to_scan)
        exclude_regex = client.config_data.get("image_filter_regex_exclude")
        filtered_images = client.filter_images(all_images, exclude_regex)

        targets = []
        for image in filtered_images.items():
            target = client.map_image_to_snyk(image)
            if target:
                targets.append(target)

        client.create_targets_file(
            targets, client.config_data.get("targets_file_output_path")
        )

    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
