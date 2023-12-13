package com.example.apiBook.test;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;
import org.thymeleaf.templateresolver.FileTemplateResolver;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

public class HtmlToThymeleafConverter {

    public static void main(String[] args) {
        String htmlFilePath = "C:/Users/hungdz/Desktop/apiBook/apiBook/src/main/resources/templates/dashboardPage.html";

        try {
            // Load HTML file using Jsoup
            File htmlFile = new File(htmlFilePath);
            Document doc = Jsoup.parse(htmlFile, "UTF-8");

            // Create a Thymeleaf template engine
            TemplateEngine templateEngine = new TemplateEngine();

            // Create a File template resolver
            FileTemplateResolver templateResolver = new FileTemplateResolver();
            templateEngine.setTemplateResolver(templateResolver);

            // Create a Thymeleaf context
            Context context = new Context();

            // Convert each HTML element to Thymeleaf tags
            Elements elements = doc.body().children();
            for (Element element : elements) {
                String thymeleafTag = convertElement(element);
                context.setVariable(element.id(), thymeleafTag);
            }

            // Process the Thymeleaf template with the context
            String result = templateEngine.process("<html><body th:inline=\"none\">[[${bodyContent}]]</body></html>", context);

            // Overwrite the original HTML file with the Thymeleaf result
            Files.write(Paths.get(htmlFilePath), result.getBytes());

            System.out.println("Conversion successful. The HTML file has been converted to Thymeleaf.");
        } catch (IOException e) {
            System.out.println("Conversion failed. Error: " + e.getMessage());
        }
    }

    private static String convertElement(Element element) {
        StringBuilder thymeleafTag = new StringBuilder();
        thymeleafTag.append("<");
        thymeleafTag.append(element.tagName());

        // Convert attributes
        for (org.jsoup.nodes.Attribute attribute : element.attributes()) {
            thymeleafTag.append(" ");
            thymeleafTag.append(attribute.getKey());
            thymeleafTag.append("=\"");
            thymeleafTag.append(attribute.getValue());
            thymeleafTag.append("\"");
        }

        // Convert children elements recursively
        if (element.children().isEmpty()) {
            thymeleafTag.append(" th:text=\"${");
            thymeleafTag.append(element.id());
            thymeleafTag.append("}\"></");
            thymeleafTag.append(element.tagName());
            thymeleafTag.append(">");
        } else {
            thymeleafTag.append(">");
            for (Element child : element.children()) {
                thymeleafTag.append(convertElement(child));
            }
            thymeleafTag.append("</");
            thymeleafTag.append(element.tagName());
            thymeleafTag.append(">");
        }
        return thymeleafTag.toString();
    }
}
