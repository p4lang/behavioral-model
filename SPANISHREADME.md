# Modelo de Comportamiento (bmv2)

![Estado de compilación](https://github.com/p4lang/behavioral-model/workflows/Test/badge.svg?branch=main)

Esta es la segunda versión del switch de software de referencia P4, apodado bmv2 (para modelo de comportamiento versión 2). El switch de software está escrito en C++11. Toma como entrada un archivo JSON generado a partir de su programa P4 por un [compilador P4](https://github.com/p4lang/p4c) e interpreta para implementar el comportamiento de procesamiento de paquetes especificado por ese programa P4.

Este repositorio contiene código para varias variaciones del modelo de comportamiento, por ejemplo, `simple_switch`, `simple_switch_grpc`, `psa_switch`, etc. Consulta [aquí](targets/README.md) para más detalles sobre las diferencias entre estos.

**bmv2 no está destinado a ser un switch de software de calidad de producción**. Está destinado a ser utilizado como una herramienta para desarrollar, probar y depurar planos de datos P4 y el software del plano de control escrito para ellos. Como tal, el rendimiento de bmv2, en términos de rendimiento y latencia, es significativamente menor que el de un switch de software de calidad de producción como [Open vSwitch](https://www.openvswitch.org/). Para más información sobre el rendimiento de bmv2, consulta este [documento](docs/performance.md).

## Instalación de bmv2

### Instalación de versiones empaquetadas de bmv2

bmv2 tiene soporte de paquetes para varias distribuciones de [Ubuntu](#ubuntu) y [Debian](#debian).

#### Ubuntu

Un paquete bmv2 está disponible en los siguientes repositorios para Ubuntu 20.04 y versiones más nuevas.

```bash
. /etc/os-release
echo "deb http://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/ /" | sudo tee /etc/apt/sources.list.d/home:p4lang.list
curl -fsSL "https://download.opensuse.org/repositories/home:/p4lang/xUbuntu_${VERSION_ID}/Release.key" | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/home_p4lang.gpg > /dev/null
sudo apt update
sudo apt install p4lang-bmv2
```
