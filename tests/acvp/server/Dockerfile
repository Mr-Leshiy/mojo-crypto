# NIST's ACVP Gen/Vals (https://github.com/usnistgov/ACVP-Server), built from a
# pinned release: the Orleans node that computes the crypto (run by default),
# plus the GenValAppRunner CLI that generates vector sets from a registration
# (exec'd into the running container by tests/acvp/read_acvp_vectors.py).

ARG DOTNET_VERSION=8.0

FROM mcr.microsoft.com/dotnet/sdk:${DOTNET_VERSION} AS build
ARG ACVP_SERVER_VERSION=v1.1.0.43
RUN git clone --depth 1 --branch ${ACVP_SERVER_VERSION} \
        https://github.com/usnistgov/ACVP-Server.git /src
WORKDIR /src
# The build props live in _config/ and have to be linked into the repo root,
# per the upstream README's "Sym Links" section.
RUN ln -sf _config/Directory.Build.props Directory.Build.props \
    && ln -sf _config/Directory.Packages.props Directory.Packages.props
COPY sharedappsettings.json gen-val/samples/sharedappsettings.json
RUN dotnet publish -c Release -o /out/orleans \
        gen-val/samples/NIST.CVP.ACVTS.Orleans.ServerHost/NIST.CVP.ACVTS.Orleans.ServerHost.csproj \
    && dotnet publish -c Release -o /out/genval \
        gen-val/samples/GenValAppRunner/src/NIST.CVP.ACVTS.Generation.GenValApp.csproj

FROM mcr.microsoft.com/dotnet/aspnet:${DOTNET_VERSION}
COPY --from=build /out /app
EXPOSE 30000 8081
CMD ["dotnet", "/app/orleans/NIST.CVP.ACVTS.Orleans.ServerHost.dll"]
