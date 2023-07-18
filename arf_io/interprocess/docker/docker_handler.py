import docker

from arf_io.exceptions import ArfDockerConnectionError, ModuleExecutionError
from arf_io.ui import ArfLogger


class DockerHandler:

    def __init__(self):
        self.logger = ArfLogger.instance()
        self.created_images = set()
        try:
            self.client = docker.from_env()
        except Exception as e:
            raise ArfDockerConnectionError(f"Cannot connect to docker: {e}") from e

    def run_and_delete(self, dockerfile_path: str, container_name: str, params: dict, timeout: int,
                       use_exit_code_for_success: bool) -> tuple[int, str]:
        params.update({'TIMEOUT': int(timeout / 2)})  # reserve half of the time for build and cleanup
        port_mapping = {params.get('LPORT'): params.get('LPORT')} if 'LPORT' in params else {}
        container = None
        try:
            self.logger.debug(f"Now handing over to Docker using env vars {params}...", 1)
            image, _ = self.client.images.build(path=dockerfile_path, tag=container_name, rm=True)
            self.created_images.add(image.id)  # track created images
            container = self.client.containers.run(container_name, detach=True, environment=params, ports=port_mapping)
            self.logger.debug(f"Image has been built, started module in docker container {container.id}", 1)

            response = container.wait(timeout=timeout)
            exit_code = response["StatusCode"]
            output = container.logs().decode('utf-8')
            if not use_exit_code_for_success and exit_code > 0:
                raise ModuleExecutionError(
                    f"Module execution failed with exit code {exit_code} and output '{output.strip()}'")
            else:
                self.logger.debug(f"Retrieved logs: {output.strip()}", 1)
                self.logger.success(f"Docker-based module has been executed successfully.")

            self.logger.debug("Execution done, containers will be stopped and deleted.", 1)
            container.stop()
            container.remove()
            return exit_code, output
        except Exception:
            if container:
                self.logger.warn(f"Execution of docker-based module {container.id} failed or timed out.")
            else:
                self.logger.warn(f"Building of docker image failed or timed out.")
            raise

    def remove_images(self):
        self.logger.debug("Now cleaning up orphaned docker images...", 1)
        for image in self.created_images:
            try:
                self.client.images.remove(image, force=True)
                self.logger.debug(f"Deleted image: {image}", 2)
            except Exception as e:
                self.logger.debug(f"Error deleting image {image}: {e}", 2)
