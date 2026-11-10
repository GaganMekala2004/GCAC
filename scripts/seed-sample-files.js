const fs = require('fs');
const path = require('path');

const baseDir = path.resolve(__dirname, '..');
const sampleReposDir = path.join(baseDir, 'sample-repos');

function writeFile(relPath, content) {
    const fullPath = path.join(sampleReposDir, relPath);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, content.trim(), 'utf-8');
}

// 1. customer-service
writeFile('customer-service/pom.xml', `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <groupId>com.example</groupId>
    <artifactId>customer-service</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>3.1.2</version>
    </parent>
    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
    </dependencies>
</project>`);

writeFile('customer-service/src/main/java/com/example/customer/config/SecurityConfig.java', `package com.example.customer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/admin/**").permitAll()
                .anyRequest().authenticated()
            );
        return http.build();
    }
}`);

writeFile('customer-service/src/main/java/com/example/customer/controller/DocumentDownloadController.java', `package com.example.customer.controller;

import java.io.File;

public class DocumentDownloadController {
    public File downloadFile(String filename) {
        File file = new File("/var/data/docs/" + filename);
        return file;
    }
}`);

// 2. payments-api
writeFile('payments-api/PaymentsAPI.sln', `
Microsoft Visual Studio Solution File, Format Version 12.00
# Visual Studio Version 17
Project("{FAE04EC0-301F-11D3-BF4B-00C04F79EFBC}") = "PaymentsAPI", "src\\PaymentsAPI\\PaymentsAPI.csproj", "{A1111111-1111-1111-1111-111111111111}"
EndProject
Global
	GlobalSection(SolutionConfigurationPlatforms) = preSolution
		Debug|Any CPU = Debug|Any CPU
	EndGlobalSection
	GlobalSection(ProjectConfigurationPlatforms) = postSolution
		{A1111111-1111-1111-1111-111111111111}.Debug|Any CPU.ActiveCfg = Debug|Any CPU
	EndGlobalSection
EndGlobal`);

writeFile('payments-api/src/PaymentsAPI/PaymentsAPI.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>`);

writeFile('payments-api/src/PaymentsAPI/appsettings.json', `{
  "Logging": {
    "LogLevel": {
      "Default": "Information"
    }
  },
  "PaymentGateway": {
    "ApiKey": "sk_live_99887766554433221100aabbccddeeff",
    "Endpoint": "https://api.paymentgateway.internal/v1"
  }
}`);

writeFile('payments-api/src/PaymentsAPI/Controllers/PaymentController.cs', `using System.Data.SqlClient;

namespace PaymentsAPI.Controllers;

public class PaymentRequest
{
    public string AccountId { get; set; } = string.Empty;
    public decimal Amount { get; set; }
}

public class PaymentController
{
    public void Process(PaymentRequest request)
    {
        string query = "SELECT * FROM Payments WHERE AccountId = '" + request.AccountId + "' AND Amount = " + request.Amount;
        using var cmd = new SqlCommand(query);
    }
}`);

writeFile('payments-api/src/PaymentsAPI/Controllers/ReceiptController.cs', `using System.Diagnostics;

namespace PaymentsAPI.Controllers;

public class ReceiptController
{
    public void Generate(string receiptId)
    {
        Process.Start("cmd.exe", $"/c generate-receipt.bat {receiptId}");
    }
}`);

writeFile('payments-api/src/PaymentsAPI/LegacyCrypto.cs', `using System.Security.Cryptography;

namespace PaymentsAPI;

public class LegacyCrypto
{
    public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
    {
        using var des = DES.Create();
        using var encryptor = des.CreateEncryptor(key, iv);
        return encryptor.TransformFinalBlock(data, 0, data.Length);
    }
}`);

// 3. inventory-manager
writeFile('inventory-manager/src/InventoryManager/InventoryManager.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="12.0.3" />
    <PackageReference Include="System.Text.Encodings.Web" Version="4.7.0" />
  </ItemGroup>
</Project>`);

writeFile('inventory-manager/src/InventoryManager/ItemService.cs', `using Newtonsoft.Json;

namespace InventoryManager;

public class ItemService
{
    public string SerializeItem(object item)
    {
        return JsonConvert.SerializeObject(item);
    }
}`);

// 4. identity-provider
writeFile('identity-provider/Infrastructure/IvantiConfig.json', `{
  "applianceType": "Ivanti Connect Secure",
  "firmwareVersion": "22.3R1",
  "gatewayCluster": "idp-prod-us-east-1"
}`);

// 5. storefront-api
writeFile('storefront-api/src/StorefrontAPI/StorefrontAPI.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
  </PropertyGroup>
</Project>`);

writeFile('storefront-api/src/StorefrontAPI/Controllers/SearchController.cs', `namespace StorefrontAPI.Controllers;

public class SearchController
{
    public string Search(string q)
    {
        return $"<html><body><h1>Search results for {q}</h1></body></html>";
    }
}`);

// 6. gcas-agentic-e2e-test-repo
writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/GcasE2ETestApi.csproj', `<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net9.0</TargetFramework>
  </PropertyGroup>
</Project>`);

writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/SecretService.cs', `namespace GcasE2ETestApi;

public class SecretService
{
    private const string ApiKey = "sk_live_994829471928472910394829";
}`);

writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/ProductsController.cs', `using System.Data.SqlClient;

namespace GcasE2ETestApi;

public class ProductsController
{
    public void GetProduct(string id)
    {
        string query = "SELECT * FROM Products WHERE Id = '" + id + "'";
        using var cmd = new SqlCommand(query);
    }
}`);

writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/DiagnosticsController.cs', `using System.Diagnostics;

namespace GcasE2ETestApi;

public class DiagnosticsController
{
    public void Ping(string host)
    {
        Process.Start("cmd.exe", $"/c ping {host}");
    }
}`);

writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/FileController.cs', `namespace GcasE2ETestApi;

public class FileController
{
    private const string BaseDirectory = "/safe/dir";

    public string Download(string fileName)
    {
        var path = System.IO.Path.Combine(BaseDirectory, fileName);
        return path;
    }
}`);

writeFile('gcas-agentic-e2e-test-repo/src/GcasE2ETestApi/SearchController.cs', `namespace GcasE2ETestApi;

public class SearchController
{
    public string Search(string query)
    {
        return $"<div>Results for {query}</div>";
    }
}`);

console.log('Sample repository source files written successfully.');

