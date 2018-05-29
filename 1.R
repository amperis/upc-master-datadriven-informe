---
  title: "Práctica Data Driven Security"
author: 'Grupo G: Yaneth Gonzalez, Miriam Jiménez, Anabel Vilchez, Alejandro Moreno'
date: "`r Sys.Date()`"
output:
  html_document:
  theme: united
toc: yes
pdf_document:
  toc: yes
---
  
  ```{r setup, include = FALSE}
knitr::opts_chunk$set(
  collapse = TRUE,
  comment = "#>"
)
```

# 1. Introducción

El propósito de la práctica es evidenciar las posibles vulnerabilidades industriales que pueden darse en diferentes países. La pregunta que intentamos responder es si **existe algun pais más propenso a tener vulnerabilidades industriales**.

Para ello, buscaremos en [Shodan](http://www.shodan.io) todos los dispositivos industriales públicos en Internet y lo cruzaremos con las vulnerabilidades que tengan este tipo de modelos de dispositivos industriales públicos en la [Common Vulnerabilities and Exposures](https://cve.mitre.org). El resultado lo representaremos en un mapa y realizaremos un análisis.

Shodan es un motor de búsquedas que ofrece información sobre equipos conectados a Internet ya sean routers, servidores, cámaras de videovigilancia, maquinaria industrial o cualquier dispositivo conectado. Permite buscar información masiva de los disposicitos y hacer un filtrado según los intereses que tengamos.

Los paquetes utilizados para la obtención de las fuentes de datos y cálculos en R pueden encontrarse en:
  
  - https://github.com/amperis/upc-master-datadriven

Esta guía puede encontratse en:
  
  - https://github.com/amperis/upc-master-datadriven-informe


# 2. Descripción de los modelos de datos

Las fuentes de datos que utilizaremos en la práctica serán las siguientes:
  
  - Fuente de datos con dispositivos industriales según fabricantes
- Fuente de datos Shodan de dispositivos industriales accesibles desde Internet
- Fuente de datos de CVE 

A continuación se describen las características de cada una de las fuentes de datos.

## 2.1 Fuente de datos con dispositivos industriales según fabricantes

Esta fuente de datos es un archivo CSV generado manualmente a través de los diferentes dispositivos industriales más comunes actualmente. Nos hemos basado en diferente documentacion técnica disponible en Internet así como en la documentación impartida en el máster. Un ejemplo de esta información se puede enconrar en la siguiente URL:
  
  - https://cybersecuritylaboratory.wordpress.com/2016/10/05/utilizando-shodan-para-encontrar-sistemas-de-control-industrial

Esta lista debe actualizarse a medida que se conozcan más fabricantes. Las cabeceras de dicha tabla son las siguientes:
  
  - Fabricante: string con el numbre del fabricante del dispositivo industrial.
- Producto: string con el modelo del producto industrial.
- Cadena de búsqueda: string de búsqueda en Shodan.

A continuación se muestran los 15 primeros regisotros de este CSV:
  
  ```{r, echo=FALSE, cache=TRUE}
library(devtools)
library(xtable)
library(RCurl)
library(dplyr)
library(knitr)
library(ggplot2)

dispositivos_industriales<-read.csv(text=getURL("https://raw.githubusercontent.com/amperis/upc-master-datadriven/master/R/SHODAN/FUENTESDATOS/ORIG/dispositivos_industriales.csv"), head=TRUE, sep=";", stringsAsFactors = FALSE)
kable(head(dispositivos_industriales,n=15))
```

Actualmente se disponen de:
  
  ```{r, echo=FALSE, cache=TRUE}
cat("un total de",nrow(dispositivos_industriales), "dispositivos industriales") 
```


## 2.2 Fuente de datos Shodan de dispositivos industriales accesibles desde Internet

Esta fuente de datos es un archivo de datos CVE obtenida a través de un proceso interativo programado en R, desde el cual, por cada dispositivo industrial obtenido del punto anterior es buscado en Shodan. Esta búsqueda nos devuelve diferente información del dispositivo industrial encontrado y público en Internet.

Esta lista puede actualizarse desde el siguiente programa disponible....

Las cabeceras del CVE obtenido son las siguientes:
  
  Campo   | Descripcion
------------------- | -----------------------------------------
  v_fabricante |  string con el nombre del fabricante del dispositivo industrial
v_producto | string con el modelo del producto del dispositivo industrial
v_cadena_busqueda | string con la cadena de búsqueda Shodan que se ha utilizado para encontrar este dispositivo
aux.matches.ip_str |  string con la IP publica del dispositivo en formato ICANN de 32 bits
aux.matches.isp | string con el nombre comercial del ISP (Internet Service Provider) de dicha direccion IP
aux.matches.location.city | string de la ciudad donde está ubicada físicamente dicha IP
aux.matches.location.longitude | string con la coordenada de longitud geografica
aux.matches.location.latitude | strinf con la coordenada de latitud geografica
aux.matches.location.country_name | string con el país 
aux.matches.location.country_code3 | strinf con el país en formato ISO-3166.1
aux.matches.os.au | string con el identificador del Sistema Autónomo al que pertenece la IP

A continuación se muestran los 10 primeros regisotros de este CVE:
  
  ```{r, echo=FALSE, cache=TRUE}
dispositivos_industriales_shodan<-read.csv(text=getURL("https://raw.githubusercontent.com/amperis/upc-master-datadriven/master/R/SHODAN/FUENTESDATOS/ORIG/dispositivos_industriales_shodan.csv"),head=TRUE, sep=";", stringsAsFactors = FALSE)
kable(head(dispositivos_industriales_shodan,n=10))
```

Actualmente se disponen de:
  
  ```{r, echo=FALSE, cache=TRUE}
cat("un total de",nrow(dispositivos_industriales_shodan), "dispositivos industriales") 
```

La distribución de fabricantes encontardos es la siguiente:
  
  ```{r, echo=FALSE, cache=TRUE}
suma<-table(dispositivos_industriales_shodan$v_fabricante)
suma<-as.data.frame(suma)
suma$Var1 <- factor(suma$Var1, levels = suma$Var1[order(-suma$Freq,decreasing = TRUE)])

ggplot(dat=suma, aes(y=Freq, x=Var1)) +
  theme_bw() + 
  geom_bar(stat = "identity") +
  coord_flip() +
  labs(x="Fabricantes", y="Numero de dispositivos")

```

La distribución de países encontrados es la siguiente:
  
  ```{r, echo=FALSE, cache=TRUE}
library(rworldmap)
suma<-table(dispositivos_industriales_shodan$aux.matches.location.country_name)
suma<-as.data.frame(suma) 
mapa=joinCountryData2Map(suma,joinCode="NAME",nameJoinColumn="Var1",verbose=FALSE)
mapCountryData(mapa,nameColumnToPlot="Freq",mapTitle="Paises con mÃ¡s dispositivos industriales")
```

## 2.3 Fuente de datos de CVE 

Dentro del respositorio "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", podemos encontrar conjuntos de datos de estándares de seguridad.

A continuación se muestran los 3 primeros registros de CVE:
  
  ```{r, echo=FALSE, cache=TRUE}
download.file(url = "https://github.com/r-net-tools/security.datasets/raw/master/net.security/sysdata.rda", destfile = sysdatarda <- tempfile())
load(sysdatarda)
cves <- netsec.data$datasets$cves
cpes <- netsec.data$datasets$cpes
cwes <- netsec.data$datasets$cwes
capec <- netsec.data$datasets$capec
kable(head(cves,n=3))
```


Como podemos ver, para cada entrada del CVE se recogen diferentes informaciones, divididas en campos (columnas):
  
  -cve.id: Identificador del CVE
-affects: 
  -problem.type
-references
-description: Breve descripción de la vulnerabilidad o exposición de seguridad.
-vulnerable.configuration
-cvss3.vector	
-cvss3.av	
-cvss3.ac	
-cvss3.pr	
-cvss3.ui	
-cvss3.s	
-cvss3.c	
-cvss3.i	
-cvss3.a	
-cvss3.score	
-cvss3.severity	
-cvss3.score.exploit	
-cvss3.score.impact	
-cvss2.vector	
-cvss2.av	
-cvss2.ac	
-cvss2.au	
-cvss2.c	
-cvss2.i	
-cvss2.a	
-cvss2.score	
-cvss2.score.exploit	
-cvss2.score.impact	
-cvss2.getallprivilege	
-cvss2.getusrprivilege	
-cvss2.getothprivilege	
-cvss2.requsrinter	
-published.date: Fecha de publicación del CVE.
-last.modified: Fecha de modificación del CVE. 


Actualmente se disponen de:
  
  ```{r, echo=FALSE, cache=TRUE}
cat("un total de",nrow(cves), "vulnerabilidades") 
```

# 3. Objetivos del análisis de datos

# 4. Análisis de datos

A continuación se analizan cuales son los 10 fabricantes que más vulnerabilidades tienen en sus dispostivos industriales:
  
  ```{r, echo=FALSE, cache=TRUE}
download.file(url = "https://raw.githubusercontent.com/amperis/upc-master-datadriven/master/R/CALCULOVULS/RESULTADOS/vuls_dispositivos_industriales.rda", destfile = sysdatarda <- tempfile())
load(sysdatarda)
#dispositivos_industriales_vuls
aux<-dispositivos_industriales_vuls %>% group_by(buscar_fabricante) %>% summarize(vulnerabilidades=sum(vuls))
aux<-as.data.frame(aux)
aux<-aux[order(aux[,2],decreasing = TRUE),]
aux$buscar_fabricante <- factor(aux$buscar_fabricante, levels = aux$buscar_fabricante[order(-aux$vulnerabilidades,decreasing = TRUE)])
aux<-head(aux,n=10)

ggplot(dat=aux, aes(y=vulnerabilidades, x=buscar_fabricante)) +
  theme_bw() + 
  geom_bar(stat = "identity") +
  coord_flip() +
  labs(x="Fabricantes", y="Numero de vulnerabilidades encontradas")
```

A continuación se analizan cuales son los países que más vulnerablidades tienen:
  
  ```{r, echo=FALSE, cache=TRUE}
download.file(url = "https://raw.githubusercontent.com/amperis/upc-master-datadriven/master/R/CALCULOVULS/RESULTADOS/vuls_dispositivos_industriales_shodan.rda", destfile = sysdatarda <- tempfile())
load(sysdatarda)
aux<-dispositivos_industriales_shodan_vuls %>% group_by(country) %>% summarize(vulnerabilidades=sum(vuls))
aux<-as.data.frame(aux)
aux<-aux[order(aux[,2],decreasing = TRUE),]
aux$country <- factor(aux$country, levels = aux$country[order(-aux$vulnerabilidades, decreasing = TRUE)])
aux<-head(aux,n=20)

ggplot(dat=aux, aes(y=vulnerabilidades, x=country)) +
  theme_bw() + 
  geom_bar(stat = "identity") +
  coord_flip() +
  labs(x="Fabricantes", y="Número de vulnerabilidades encontradas")

```

# 5. Conclusiones

# 6. Referencias utilizadas

- [Hacer y documentar un paquete de R en 20 minutos](https://mauriciogtec.github.io/rGallery/entries/tutoriales/crear_paquetes/crear_paquete.html)
- [R Markdown Cheat Sheet](https://www.rstudio.com/wp-content/uploads/2015/02/rmarkdown-cheatsheet.pdf)
