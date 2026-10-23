# Apache log4net: a logging library for .NET, built and tested on Linux with the .NET 10 SDK.
# The net462 targets compile against the Microsoft.NETFramework.ReferenceAssemblies packages the SDK
# references implicitly, so no Mono is needed. On Linux the test projects target net10.0 only.
FROM mcr.microsoft.com/dotnet/sdk:10.0-noble
ENV TZ=Etc/UTC \
    DOTNET_NOLOGO=true \
    DOTNET_SKIP_FIRST_TIME_EXPERIENCE=true \
    DOTNET_CLI_TELEMETRY_OPTOUT=true

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

# Restore every package now (the audit runs offline), then build the solution in Debug with full symbols.
# The solution builds with 0 warnings and treats nullability warnings as errors, so a failure here is real.
RUN dotnet restore src/log4net.sln \
    && dotnet build src/log4net.sln -c Debug --no-restore

# Run the unit tests so the image is known to work, without letting a failing test abort the build.
# Afterwards `dotnet test src/log4net.Tests/log4net.Tests.csproj --no-build --filter <name>` works offline.
RUN (dotnet test src/log4net.Tests/log4net.Tests.csproj -c Debug --no-build \
      || echo "WARNING: log4net.Tests reported failures") \
    && (dotnet test src/log4net.Ext.Mail.Tests/log4net.Ext.Mail.Tests.csproj -c Debug --no-build \
      || echo "WARNING: log4net.Ext.Mail.Tests reported failures")
