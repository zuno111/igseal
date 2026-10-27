# 봉인 뷰어 렌더러 자산 (STUDIO ig 기존 툴 재사용)

봉인 뷰어가 포맷별로 사용하는 사장님 웹 툴. 전부 오프라인 동작하도록 CDN→로컬 vendor 치환, 외부 폰트 제거 완료.

- layerroom.html — 이미지 (레이어룸, ag-psd 로컬화)
- webmax.html — 3D 모델 (three.js r128 로컬화)
- splat4d.html — 4D/3DGS .ply (three.js 로컬화)
- cutroom.html — 영상 편집기 (원본, 편집용 CDN 다수 — 뷰어에선 단순재생으로 대체 예정)
- baekji-word.html — 문서 워드
- vendor/ — three.js r128 + addons, ag-psd (npm에서 추출, 오프라인)

검증: Playwright로 file:// 로드 시 webmax/splat4d three.js 로드·렌더·에러0, layerroom ag-psd 로드·에러0 확인.
