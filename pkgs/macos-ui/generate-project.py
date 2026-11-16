#!/usr/bin/env python3
"""Generate the checked-in Xcode project without third-party tooling."""
import hashlib
import pathlib
import plistlib

root = pathlib.Path(__file__).resolve().parent
project = root / "SeccyUI.xcodeproj"
project.mkdir(exist_ok=True)
objects = {}

def ident(name):
    return hashlib.sha256(name.encode()).hexdigest()[:24].upper()

def add(identifier, isa, **fields):
    key = ident(identifier)
    objects[key] = dict(isa=isa, **fields)
    return key

files = {}
for path in ["Sources/Copy.swift", "Sources/Copy.generated.swift", "Sources/Notifications.swift", "Sources/UITrace.swift", "Sources/AuthorizationView.swift", "Sources/Bridge.swift", "Gallery/GalleryApp.swift"]:
    files[path] = add(path, "PBXFileReference", path=path, sourceTree="<group>", lastKnownFileType="sourcecode.swift")
files["Gallery/Info.plist"] = add("Gallery/Info.plist", "PBXFileReference", path="Gallery/Info.plist", sourceTree="<group>", lastKnownFileType="text.plist.xml")
products = []
targets = []
for name, kind, paths, product_path, product_type in [
    ("SeccyUI", "com.apple.product-type.library.static", ["Sources/Copy.swift", "Sources/Copy.generated.swift", "Sources/Notifications.swift", "Sources/UITrace.swift", "Sources/AuthorizationView.swift", "Sources/Bridge.swift"], "libSeccyUI.a", "archive.ar"),
    ("Gallery", "com.apple.product-type.application", ["Sources/Copy.swift", "Sources/Copy.generated.swift", "Sources/Notifications.swift", "Sources/UITrace.swift", "Sources/AuthorizationView.swift", "Sources/Bridge.swift", "Gallery/GalleryApp.swift"], "Seccy UI Gallery.app", "wrapper.application"),
]:
    product = add(name + " product", "PBXFileReference", path=product_path, sourceTree="BUILT_PRODUCTS_DIR", explicitFileType=product_type)
    products.append(product)
    builds = [add(name + path, "PBXBuildFile", fileRef=files[path]) for path in paths]
    phase = add(name + " sources", "PBXSourcesBuildPhase", buildActionMask=2147483647, files=builds, runOnlyForDeploymentPostprocessing=0)
    copy_phase = add(name + " copy", "PBXShellScriptBuildPhase", buildActionMask=2147483647,
        files=[], inputPaths=[], outputPaths=[], alwaysOutOfDate=1,
        runOnlyForDeploymentPostprocessing=0, shellPath="/bin/bash",
        shellScript='export PATH="$HOME/.cargo/bin:$PATH"\ncd "$SRCROOT/../.."\ncargo run --quiet -p seccy_copy --example generate-swift',
        name="Generate shared Fluent copy")
    phases = [copy_phase, phase]
    if name == "Gallery":
        phases.append(add("Gallery icon", "PBXShellScriptBuildPhase", buildActionMask=2147483647,
            files=[], inputPaths=["$(SRCROOT)/../../assets/icon-macos.png", "$(SRCROOT)/../macos/scripts/build-icon.sh"],
            outputPaths=["$(TARGET_BUILD_DIR)/$(UNLOCALIZED_RESOURCES_FOLDER_PATH)/Seccy.icns"],
            runOnlyForDeploymentPostprocessing=0, shellPath="/bin/bash",
            shellScript='bash "$SRCROOT/../macos/scripts/build-icon.sh" "$TARGET_BUILD_DIR/$UNLOCALIZED_RESOURCES_FOLDER_PATH/Seccy.icns"',
            name="Build Seccy app icon"))
    configs = []
    for config in ["Debug", "Release"]:
        settings = dict(ALWAYS_SEARCH_USER_PATHS="NO", PRODUCT_NAME="SeccyUI" if name == "SeccyUI" else "Seccy UI Gallery", SWIFT_VERSION="5.0", MACOSX_DEPLOYMENT_TARGET="12.0", SDKROOT="macosx", CODE_SIGN_STYLE="Automatic", SWIFT_OPTIMIZATION_LEVEL="-Onone" if config == "Debug" else "-O", ENABLE_TESTABILITY="YES" if config == "Debug" else "NO")
        if name == "Gallery":
            settings.update(CODE_SIGN_IDENTITY="-", CODE_SIGN_STYLE="Manual", GENERATE_INFOPLIST_FILE="NO", INFOPLIST_FILE="Gallery/Info.plist", PRODUCT_BUNDLE_IDENTIFIER="fyi.seccy.gallery", INFOPLIST_KEY_LSApplicationCategoryType="public.app-category.developer-tools", ENABLE_HARDENED_RUNTIME="YES")
        else:
            settings.update(SKIP_INSTALL="YES", DEFINES_MODULE="YES")
        configs.append(add(name + config, "XCBuildConfiguration", name=config, buildSettings=settings))
    config_list = add(name + " configs", "XCConfigurationList", buildConfigurations=configs, defaultConfigurationIsVisible=0, defaultConfigurationName="Release")
    target = add(name, "PBXNativeTarget", name=name, productName=name, productReference=product, productType=kind, buildConfigurationList=config_list, buildPhases=phases, buildRules=[], dependencies=[])
    targets.append(target)
    schemes = project / "xcshareddata/xcschemes"
    schemes.mkdir(parents=True, exist_ok=True)
    ref = f'<BuildableReference BuildableIdentifier="primary" BlueprintIdentifier="{target}" BuildableName="{product_path}" BlueprintName="{name}" ReferencedContainer="container:SeccyUI.xcodeproj"/>'
    runnable = f'<BuildableProductRunnable runnableDebuggingMode="0">{ref}</BuildableProductRunnable>' if name == "Gallery" else ""
    (schemes / f"{name}.xcscheme").write_text(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme LastUpgradeVersion="2700" version="1.3">
<BuildAction parallelizeBuildables="YES" buildImplicitDependencies="YES"><BuildActionEntries><BuildActionEntry buildForTesting="YES" buildForRunning="YES" buildForProfiling="YES" buildForArchiving="YES" buildForAnalyzing="YES">{ref}</BuildActionEntry></BuildActionEntries></BuildAction>
<LaunchAction buildConfiguration="Debug" selectedDebuggerIdentifier="Xcode.DebuggerFoundation.Debugger.LLDB" selectedLauncherIdentifier="Xcode.IDEFoundation.Launcher.LLDB" launchStyle="0" useCustomWorkingDirectory="NO" ignoresPersistentStateOnLaunch="NO" debugDocumentVersioning="YES">{runnable}</LaunchAction>
<ProfileAction buildConfiguration="Release" shouldUseLaunchSchemeArgsEnv="YES" useCustomWorkingDirectory="NO" debugDocumentVersioning="YES">{runnable}</ProfileAction>
<AnalyzeAction buildConfiguration="Debug"/><ArchiveAction buildConfiguration="Release" revealArchiveInOrganizer="YES"/>
</Scheme>
''')
group = add("products", "PBXGroup", name="Products", children=products, sourceTree="<group>")
main = add("main", "PBXGroup", children=list(files.values()) + [group], sourceTree="<group>")
configs = [add("project " + c, "XCBuildConfiguration", name=c, buildSettings={}) for c in ["Debug", "Release"]]
config_list = add("project configs", "XCConfigurationList", buildConfigurations=configs, defaultConfigurationIsVisible=0, defaultConfigurationName="Release")
pid = add("project", "PBXProject", attributes={"LastUpgradeCheck": "2700"}, buildConfigurationList=config_list, compatibilityVersion="Xcode 14.0", developmentRegion="en", hasScannedForEncodings=0, knownRegions=["en", "Base"], mainGroup=main, productRefGroup=group, projectDirPath="", projectRoot="", targets=targets)
with (project / "project.pbxproj").open("wb") as f:
    plistlib.dump(dict(archiveVersion="1", classes={}, objectVersion="56", objects=objects, rootObject=pid), f, sort_keys=False)
