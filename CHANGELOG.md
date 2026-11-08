# Changelog

## [0.1.0-beta.1](https://github.com/Serraniel/SweetCaptcha/compare/v0.1.0...v0.1.0-beta.1) (2026-11-08)


### Features

* add a help page for blocked visitors and a compatibility matrix ([#53](https://github.com/Serraniel/SweetCaptcha/issues/53)) ([a85bd87](https://github.com/Serraniel/SweetCaptcha/commit/a85bd87d38011e0286bb42dad05879db0a97a5a3)), closes [#43](https://github.com/Serraniel/SweetCaptcha/issues/43)
* add a hidden trap link for scrapers that follow every link ([#56](https://github.com/Serraniel/SweetCaptcha/issues/56)) ([279fce2](https://github.com/Serraniel/SweetCaptcha/commit/279fce26b66fe426d9f6282b4849d76ceec4b849)), closes [#46](https://github.com/Serraniel/SweetCaptcha/issues/46)
* add an optional Prometheus metrics endpoint ([#55](https://github.com/Serraniel/SweetCaptcha/issues/55)) ([44c87b4](https://github.com/Serraniel/SweetCaptcha/commit/44c87b4e1b279a3a01bb869fbbb011dba0fd3377)), closes [#44](https://github.com/Serraniel/SweetCaptcha/issues/44)
* add per-site rules that adjust scoring or force an outcome ([#50](https://github.com/Serraniel/SweetCaptcha/issues/50)) ([2a54b16](https://github.com/Serraniel/SweetCaptcha/commit/2a54b1652e10f49579f89e10e98b95058d82d09a))
* benchmark proof of work and retry memory failures with one worker ([#52](https://github.com/Serraniel/SweetCaptcha/issues/52)) ([b4faaac](https://github.com/Serraniel/SweetCaptcha/commit/b4faaacd89a64b6be69ee4998dc578e20c1f0331)), closes [#42](https://github.com/Serraniel/SweetCaptcha/issues/42)
* link the site's privacy notice and imprint from the widget ([#54](https://github.com/Serraniel/SweetCaptcha/issues/54)) ([95c32f4](https://github.com/Serraniel/SweetCaptcha/commit/95c32f415bea137f2b66094c21709231135666a7)), closes [#45](https://github.com/Serraniel/SweetCaptcha/issues/45)
* play the motion task automatically ([#58](https://github.com/Serraniel/SweetCaptcha/issues/58)) ([ff80e23](https://github.com/Serraniel/SweetCaptcha/commit/ff80e234adb3d0cf7a8e1bcab3ae8571eae68bca)), closes [#57](https://github.com/Serraniel/SweetCaptcha/issues/57)
* remember hard failures per network for 30 minutes ([#51](https://github.com/Serraniel/SweetCaptcha/issues/51)) ([f77213b](https://github.com/Serraniel/SweetCaptcha/commit/f77213ba5bc71762460091e04f2823afeb67bb3c)), closes [#40](https://github.com/Serraniel/SweetCaptcha/issues/40)


### Bug Fixes

* keep dual-stack visitors from failing token binding ([#47](https://github.com/Serraniel/SweetCaptcha/issues/47)) ([2324bd1](https://github.com/Serraniel/SweetCaptcha/commit/2324bd1f7fb72ea6fd5f7e4f5b7e0d034775aa46)), closes [#38](https://github.com/Serraniel/SweetCaptcha/issues/38)


### Documentation

* state the beta status and open gaps in the README ([#59](https://github.com/Serraniel/SweetCaptcha/issues/59)) ([c9264d1](https://github.com/Serraniel/SweetCaptcha/commit/c9264d1138bce58d750251c6986307416b4bf4f2))

## 0.1.0 (2026-11-08)


### Features

* add a threat model and close the bypass routes it found ([#30](https://github.com/Serraniel/SweetCaptcha/issues/30)) ([18b2be7](https://github.com/Serraniel/SweetCaptcha/commit/18b2be7025f2f7171d2444e41b87e2d41ea274b7))
* add an adversarial lab with maintained evasion tools ([#32](https://github.com/Serraniel/SweetCaptcha/issues/32)) ([0ab1720](https://github.com/Serraniel/SweetCaptcha/commit/0ab17202c3cbd7aeee857fbd41410b60e29a83f0)), closes [#16](https://github.com/Serraniel/SweetCaptcha/issues/16)
* add motion and stacking-order tasks aimed at AI weaknesses ([#25](https://github.com/Serraniel/SweetCaptcha/issues/25)) ([ac8b65c](https://github.com/Serraniel/SweetCaptcha/commit/ac8b65c57c40e888cea7cb35a39f973761b785fb)), closes [#24](https://github.com/Serraniel/SweetCaptcha/issues/24)
* balance proof-of-work difficulty to measured targets ([#22](https://github.com/Serraniel/SweetCaptcha/issues/22)) ([e43c783](https://github.com/Serraniel/SweetCaptcha/commit/e43c783cfcab512a24eb72f8e6eda4e23df0886f))
* self-hosted CAPTCHA with server-side bot detection ([ea3bc42](https://github.com/Serraniel/SweetCaptcha/commit/ea3bc42acc3f08da196d82af404440e7ef7f0a52))
* translate the widget into 21 languages ([#23](https://github.com/Serraniel/SweetCaptcha/issues/23)) ([dae870a](https://github.com/Serraniel/SweetCaptcha/commit/dae870aa4f17f32aeb199a6ca8c9543c936cdd28)), closes [#13](https://github.com/Serraniel/SweetCaptcha/issues/13)


### Bug Fixes

* launch Puppeteer without the sandbox in the adversarial lab ([#34](https://github.com/Serraniel/SweetCaptcha/issues/34)) ([18fb9d8](https://github.com/Serraniel/SweetCaptcha/commit/18fb9d8dd93a55f28256ccfa1a12f2a75ed43d0e)), closes [#33](https://github.com/Serraniel/SweetCaptcha/issues/33)
* remove the console-serialization check after a control experiment ([#37](https://github.com/Serraniel/SweetCaptcha/issues/37)) ([9c1e4bd](https://github.com/Serraniel/SweetCaptcha/commit/9c1e4bd4df8370c198e97fdcede2aaf80c11c1ad)), closes [#31](https://github.com/Serraniel/SweetCaptcha/issues/31)
* restrict IP data files to the service user ([451a5f5](https://github.com/Serraniel/SweetCaptcha/commit/451a5f551b753b3c252b4fdf29c7433ed24d4139))
* rework widget verification, task popup and puzzles ([#12](https://github.com/Serraniel/SweetCaptcha/issues/12)) ([b9a8ca4](https://github.com/Serraniel/SweetCaptcha/commit/b9a8ca4036c9e2f88267ae4534a7704455c19155))
* tighten IP data file permissions and resolve lint findings ([a6d4a2a](https://github.com/Serraniel/SweetCaptcha/commit/a6d4a2aad7fc1202b5ed27bd7f46e865237cf698))


### Documentation

* add a demo GIF of automatic verification to the README ([#20](https://github.com/Serraniel/SweetCaptcha/issues/20)) ([9f6e0ad](https://github.com/Serraniel/SweetCaptcha/commit/9f6e0ad4c01ecf0fa7bc16a60928532b3cb8439e)), closes [#14](https://github.com/Serraniel/SweetCaptcha/issues/14)
