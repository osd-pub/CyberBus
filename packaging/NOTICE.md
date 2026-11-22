CyberBus SDK 0.2.0

The root CyberBus workspace declares MIT OR Apache-2.0; cyberbus-transport
declares LGPL-3.0-or-later. Full texts accompany this distribution. The cyberbus
and cyberbus-cli package manifests omit Cargo license inheritance, so the SBOM
preserves NOASSERTION for their raw package metadata. EasyTier's three manifests
use license-file instead of an SPDX declaration; those exact texts are copied
and identified by hash. The embedded EasyTier component and local changes
are LGPL-3.0. See source/vendor/easytier/README.cyberbus.md for upstream commit,
retained notices, and local modifications. The combined SDK includes LGPL
components; the entire binary must not be advertised as MIT/Apache-only.

The release's DEPENDENCIES.json records the resolved dependency names, versions,
sources, license declarations and checksums from Cargo.lock. Its scope is the
target's resolved shipped-crate graph (CLI included only for desktop), including host build tools (a conservative
superset of linked code). LICENSES/ preserves third-party notice/license files.
The source archive also includes complete resolver dependency sources (including other-target metadata needed
for offline resolution) and embedded
notices, including dependencies with nonstandard license filenames. Android's
protobuf runtime and generated code use the protobuf BSD license; the Maven
runtime license and sources accompany the Android package.

Keep this notice, LICENSES, SOURCES.tar.gz, dependency manifests, and RELINK.md
with redistributed native SDK archives. Source material is included directly,
not merely an upstream URL. Ship your own application's relinkable object files
or corresponding application sources/build instructions when statically
linking it with this SDK. This SDK distribution cannot supply objects belonging
to downstream applications. Do not prohibit reverse engineering for debugging
modifications to the LGPL portion. Signing/reinstallation information needed
for a User Product is the responsibility of that product's distributor.
