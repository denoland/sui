#[cfg(any(
    all(unix, not(target_vendor = "apple")),
    all(target_vendor = "apple", target_arch = "aarch64")
))]
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

#[cfg(all(unix, not(target_vendor = "apple")))]
fn hash(name: &str) -> u32 {
    let mut h: u32 = 0;
    for c in name.bytes() {
        h = h.wrapping_add(c as u32);
    }
    h
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn build_blob(section_len: usize, name: &str) -> Vec<u8> {
    const MAGIC: u32 = 0x501e;
    const TRAILER_LEN: usize = 8 + 4 + 4;
    let mut data = vec![0u8; 4096];
    data.resize(data.len() + section_len, 0);
    data.extend_from_slice(&MAGIC.to_le_bytes());
    data.extend_from_slice(&hash(name).to_le_bytes());
    let offset = (section_len + TRAILER_LEN) as u64;
    data.extend_from_slice(&offset.to_le_bytes());
    data
}

#[cfg(all(unix, not(target_vendor = "apple")))]
fn bench_find_section(c: &mut Criterion) {
    let name = "bench_section";
    let mut group = c.benchmark_group("find_section");
    for size in [64usize, 1024, 16 * 1024, 256 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
        let data = build_blob(size, name);
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| {
                let section = libsui::find_section_in_bytes(black_box(data), black_box(name));
                black_box(section.map(|v| v.len()));
            })
        });
    }
    group.finish();
}

#[cfg(all(unix, not(target_vendor = "apple")))]
criterion_group!(benches, bench_find_section);
#[cfg(all(unix, not(target_vendor = "apple")))]
criterion_main!(benches);

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench64"]
static BENCH_64: [u8; 64] = [1; 64];
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench1k"]
static BENCH_1K: [u8; 1024] = [2; 1024];
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench16k"]
static BENCH_16K: [u8; 16 * 1024] = [3; 16 * 1024];
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench256k"]
static BENCH_256K: [u8; 256 * 1024] = [4; 256 * 1024];
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench1m"]
static BENCH_1M: [u8; 1024 * 1024] = [5; 1024 * 1024];
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
#[used]
#[link_section = "__SUI,__bench8m"]
static BENCH_8M: [u8; 8 * 1024 * 1024] = [6; 8 * 1024 * 1024];

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
fn bench_find_section_macos_arm(c: &mut Criterion) {
    let mut group = c.benchmark_group("find_section");
    for (name, size) in [
        ("__bench64", 64usize),
        ("__bench1k", 1024),
        ("__bench16k", 16 * 1024),
        ("__bench256k", 256 * 1024),
        ("__bench1m", 1024 * 1024),
        ("__bench8m", 8 * 1024 * 1024),
    ] {
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &name, |b, name| {
            b.iter(|| {
                let section = libsui::find_section(black_box(name)).unwrap();
                black_box(section.map(|v| v.len()));
            })
        });
    }
    group.finish();
}

#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
criterion_group!(benches, bench_find_section_macos_arm);
#[cfg(all(target_vendor = "apple", target_arch = "aarch64"))]
criterion_main!(benches);

#[cfg(not(any(
    all(unix, not(target_vendor = "apple")),
    all(target_vendor = "apple", target_arch = "aarch64")
)))]
fn main() {}
