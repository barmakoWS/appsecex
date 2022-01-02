package com.example.appsecex;

import java.io.StringReader;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class CWE611 {

    private final Logger logger = LoggerFactory.getLogger(CWE611.class);

    @PostMapping(path = "/xml/vul/XMLInputFactory", consumes = {MediaType.APPLICATION_XML_VALUE})
    public String xmlInputFactory(@RequestBody String xmlStr) {
        XMLStreamReader streamReader = parseWithXMLInputFactory(xmlStr);
        return readXML(streamReader);
    }

    @PostMapping(path = "/xml/vul2/XMLInputFactory", consumes = {MediaType.APPLICATION_XML_VALUE})
    public String xmlInputFactory2(@RequestBody String xmlStr) {
        XMLStreamReader streamReader = parseWithXMLInputFactory2(xmlStr);
        return readXML(streamReader);
    }

    @PostMapping(path = "/xml/safe/XMLInputFactory", consumes = {MediaType.APPLICATION_XML_VALUE})
    public String safeXmlInputFactory(@RequestBody String xmlStr) {
        XMLStreamReader streamReader = safeParseWithXMLInputFactory(xmlStr);
        return readXML(streamReader);
    }


    @PostMapping(path = "/xml/safe2/XMLInputFactory", consumes = {MediaType.APPLICATION_XML_VALUE})
    public String safeXmlInputFactory2(@RequestBody String xmlStr) {
        XMLStreamReader streamReader = parseWithXMLInputFactory2(xmlStr);
        return readXML(streamReader);
    }

    private String readXML(XMLStreamReader streamReader) {
        try {
            if (streamReader != null) {
                while (streamReader.hasNext()) {
                    //Move to next event
                    streamReader.next();

                    if (streamReader.isStartElement()) {
                        //Read foo data
                        if (streamReader.getLocalName().equalsIgnoreCase("foo")) {
                            return streamReader.getElementText();
                        }
                    }
                }
            }
        } catch (XMLStreamException e) {
            logger.error("XMLStreamException 2 : " + e.getMessage());
        }

        return "XML parse error";
    }


    private XMLStreamReader safeParseWithXMLInputFactory(String xmlString) {
        logger.debug("Convert String To XML Document with XMLInputFactory");

        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();

//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);

            return factory.createXMLStreamReader(new StringReader(xmlString));

        } catch (XMLStreamException e) {
            logger.error("XMLStreamException 1 : " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

        return null;
    }

    private XMLStreamReader parseWithXMLInputFactory(String xmlString) {
        logger.debug("Convert String To XML Document with XMLInputFactory");

        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();

//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
//            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
//            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);

            return factory.createXMLStreamReader(new StringReader(xmlString));

        } catch (XMLStreamException e) {
            logger.error("XMLStreamException 1 : " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

        return null;
    }
    private XMLStreamReader parseWithXMLInputFactory2(String xmlString) {
        logger.debug("Convert String To XML Document with XMLInputFactory");

        try {
            XMLInputFactory factory = XMLInputFactory.newInstance();

//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_DTD, "");
//            factory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            factory.setProperty(XMLInputFactory.SUPPORT_DTD, false);
//            factory.setProperty("javax.xml.stream.isSupportingExternalEntities", false);

            return factory.createXMLStreamReader(new StringReader("constant"));

        } catch (XMLStreamException e) {
            logger.error("XMLStreamException 1 : " + e.getMessage());
        } catch (Exception e) {
            logger.error("Exception: " + e.getMessage());
        }

        return null;
    }
}
