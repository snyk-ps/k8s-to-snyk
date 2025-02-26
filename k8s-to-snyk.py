import logging
import json
import re
from kubernetes import client, config
import yaml
import os
import argparse

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger("kubectl-images")


class Client:
    def __init__(self, kube_config=None, config_file="config.yaml"):
        """Initializes the Client and loads the Kubernetes configuration and configuration file."""
        self.api = self._load_kube_config(kube_config)
        self.config_data = self._load_config_file(config_file)

    def _load_config_file(self, config_file):
        """Loads configuration data from a JSON or YAML file."""
        try:
            if not os.path.exists(config_file):
                logger.warning(
                    f"Config file {config_file} not found. Using default empty config."
                )
                return {}

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

    def get_all_images(self, namespaces=None):
        """Fetches all image names across specified namespaces or all if none are provided."""
        try:
            all_images = set()
            if namespaces:
                for namespace in namespaces:
                    pods = self.api.list_namespaced_pod(
                        namespace=namespace, watch=False
                    )
                    for pod in pods.items:
                        for container in pod.spec.containers:
                            all_images.add(container.image)
                        if pod.spec.init_containers:
                            for init_container in pod.spec.init_containers:
                                all_images.add(init_container.image)
            else:
                pods = self.api.list_pod_for_all_namespaces(watch=False)
                for pod in pods.items:
                    for container in pod.spec.containers:
                        all_images.add(container.image)
                    if pod.spec.init_containers:
                        for init_container in pod.spec.init_containers:
                            all_images.add(init_container.image)

            return sorted(list(all_images))

        except client.exceptions.ApiException as e:
            logger.error(f"Error fetching pod information: {e}")
            return None
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {e}")
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

    def map_image_to_snyk(self, namespace, image_name):
        """Maps an image to Snyk org and integration ID based on config."""
        snyk_mapping = self.config_data.get("snyk_org_mapping", {})
        if not snyk_mapping:
            return None

        map_on = snyk_mapping.get("map_on")
        if map_on == "label":
            label_name = snyk_mapping.get("label")
            pod_labels = self.get_image_labels(namespace, image_name)
            if not pod_labels:
                return None

            for pod_name, labels in pod_labels.items():
                label_value = labels.get(label_name)
                if label_value and snyk_mapping.get("values"):
                    for map_value, snyk_data in snyk_mapping["values"].items():
                        if label_value == map_value:
                            return {
                                "orgId": snyk_data.get("snyk_org_id"),
                                "integrationId": snyk_data.get("snyk_integration_id"),
                            }
        elif map_on == "namespace":
            if snyk_mapping.get("values"):
                for map_value, snyk_data in snyk_mapping["values"].items():
                    if namespace == map_value:
                        return {
                            "orgId": snyk_data.get("snyk_org_id"),
                            "integrationId": snyk_data.get("snyk_integration_id"),
                        }

        return None

    def get_image_labels(self, namespace, image_name):
        """Fetches labels associated with pods using a specific image."""
        try:
            pod_labels = {}
            pods = self.api.list_namespaced_pod(namespace=namespace, watch=False)

            for pod in pods.items:
                for container in pod.spec.containers:
                    if container.image == image_name:
                        pod_labels[pod.metadata.name] = pod.metadata.labels or {}
                if pod.spec.init_containers:
                    for init_container in pod.spec.init_containers:
                        if init_container.image == image_name:
                            pod_labels[pod.metadata.name] = pod.metadata.labels or {}

            return pod_labels

        except client.exceptions.ApiException as e:
            logger.error(
                f"Error fetching pod labels for image {image_name} in namespace {namespace}: {e}"
            )
            return None
        except Exception as e:
            logger.exception(f"An unexpected error occurred: {e}")
            return None

    def create_targets_file(self, images_data, output_file="imported-targets.json"):
        """Generates targets file"""
        targets = []
        for image_data in images_data:
            targets.append(
                {
                    "orgId": image_data["orgId"],
                    "integrationId": image_data["integrationId"],
                    "target": {"name": image_data["image"]},
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
        all_images = client.get_all_images(namespaces=namespaces_to_scan)
        exclude_regex = client.config_data.get("image_filter_regex_exclude")
        filtered_images = client.filter_images(all_images, exclude_regex)

        images_data = []
        for image in filtered_images:
            for namespace in namespaces_to_scan:
                snyk_mapping = client.map_image_to_snyk(namespace, image)
                if snyk_mapping:
                    images_data.append(
                        {
                            "image": image,
                            "orgId": snyk_mapping["orgId"],
                            "integrationId": snyk_mapping["integrationId"],
                        }
                    )
                    break

        client.create_targets_file(
            images_data, client.config_data.get("targets_file_output_path")
        )

    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
