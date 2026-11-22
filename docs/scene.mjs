const TAU = 2 * Math.PI;
const PALETTE = {
  mint: [155, 247, 214],
  violet: [168, 135, 232],
  rose: [246, 160, 192],
  peach: [255, 194, 145],
  ink: [57, 37, 91],
};
const SIGNALS = [
  { kind: "info", color: PALETTE.mint, point: [-1.98, -.12, .75] },
  { kind: "warning", color: PALETTE.peach, point: [1.92, -.06, .51] },
  { kind: "critical", color: PALETTE.rose, point: [.27, .35, -1.79] },
];
const FACES = [
  [0, 1, 2, 3], [4, 7, 6, 5], [0, 4, 5, 1],
  [1, 5, 6, 2], [2, 6, 7, 3], [3, 7, 4, 0],
];

const color = (rgb, alpha) => `rgba(${rgb.join(",")},${alpha})`;
const clamp = (value, lower, upper) => Math.max(lower, Math.min(upper, value));

function ring(radius, y, segments, pitch = 0, yaw = 0) {
  return Array.from({ length: segments + 1 }, (_, i) => {
    const angle = TAU * i / segments;
    const x = radius * Math.cos(angle);
    const z = radius * Math.sin(angle) * Math.cos(pitch);
    return [x * Math.cos(yaw) - z * Math.sin(yaw), y + radius * Math.sin(angle) * Math.sin(pitch),
      x * Math.sin(yaw) + z * Math.cos(yaw)];
  });
}

function cube([cx, cy, cz], size, height, turn) {
  const corners = [[-1, -1], [1, -1], [1, 1], [-1, 1]];
  return [-1, 1].flatMap((side) => corners.map(([u, v]) => {
    const [x, z] = [u * size / 2, v * size / 2];
    return [cx + x * Math.cos(turn) - z * Math.sin(turn), cy + side * height / 2,
      cz + x * Math.sin(turn) + z * Math.cos(turn)];
  }));
}

const lattice = [
  ...[.76, 1.17, 1.52, 1.88, 2.26, 2.67].map((radius) => ring(radius, -.68, 64)),
  ring(1.57, .02, 80, .86, .2),
  ring(1.34, .12, 80, -.77, -.61),
  ring(1.88, .04, 80, .44, 1.32),
];
const ticks = Array.from({ length: 48 }, (_, i) => {
  const a = TAU * i / 48;
  return [2.57, i % 4 === 0 ? 2.77 : 2.66].map((r) => [r * Math.cos(a), -.68, r * Math.sin(a)]);
});
const satellites = Array.from({ length: 18 }, (_, i) => {
  const angle = i * 2.399963;
  const radius = 1.18 + (i % 6) * .24;
  return [Math.cos(angle) * radius, -.39 + (i % 5) * .25, Math.sin(angle) * radius];
});
const dust = Array.from({ length: 58 }, (_, i) => [
  (i * .38196601125) % 1,
  (i * .61803398875 + .13 * Math.sin(i)) % 1,
  .4 + (i % 7) * .11,
]);

export function mountSignalField(canvas, toggle) {
  const ctx = canvas.getContext("2d");
  if (!ctx) {
    toggle.disabled = true;
    return { update() {} };
  }

  const preference = window.matchMedia("(prefers-reduced-motion: reduce)");
  let width = 0;
  let height = 0;
  let yaw = -.56;
  let pitch = .49;
  let clock = 0;
  let lastFrame = 0;
  let animation = 0;
  let inView = true;
  let paused = preference.matches;
  let userChoice = false;
  let drag = null;
  let counts = { info: 0, warning: 0, critical: 0 };

  function project([x, y, z]) {
    const horizontal = x * Math.cos(yaw) - z * Math.sin(yaw);
    const planeDepth = x * Math.sin(yaw) + z * Math.cos(yaw);
    const vertical = y * Math.cos(pitch) - planeDepth * Math.sin(pitch);
    const depth = y * Math.sin(pitch) + planeDepth * Math.cos(pitch);
    const unit = Math.min(width / 6.0, height / 4.35) * 7.4 / (7.4 - depth);
    return { x: width * .5 + horizontal * unit, y: height * .51 - vertical * unit, depth, unit };
  }

  function path(points, close = false) {
    ctx.beginPath();
    ctx.moveTo(points[0].x, points[0].y);
    for (const point of points.slice(1)) ctx.lineTo(point.x, point.y);
    if (close) ctx.closePath();
  }

  function stroke(points, rgb, alpha, width = 1) {
    path(points.map(project));
    ctx.strokeStyle = color(rgb, alpha);
    ctx.lineWidth = width;
    ctx.stroke();
  }

  function solid(origin, size, thickness, turn, rgb, fill, edge) {
    const vertices = cube(origin, size, thickness, turn).map(project);
    const faces = FACES.map((ids) => {
      const points = ids.map((id) => vertices[id]);
      return { points, depth: points.reduce((total, point) => total + point.depth, 0) / 4 };
    }).sort((a, b) => a.depth - b.depth);
    for (const [index, face] of faces.entries()) {
      path(face.points, true);
      ctx.fillStyle = color(rgb, fill * (.69 + index / 10));
      ctx.fill();
      ctx.strokeStyle = color(rgb, edge);
      ctx.lineWidth = 1;
      ctx.stroke();
    }
  }

  function dot(point, rgb, radius, opacity) {
    ctx.beginPath();
    ctx.arc(point.x, point.y, radius, 0, TAU);
    ctx.fillStyle = color(rgb, opacity);
    ctx.fill();
  }

  function halo([x, y, z], rgb, radius, opacity) {
    const screen = project([x, y, z]);
    const gradient = ctx.createRadialGradient(screen.x, screen.y, 0, screen.x, screen.y, radius);
    gradient.addColorStop(0, color(rgb, opacity));
    gradient.addColorStop(1, color(rgb, 0));
    ctx.fillStyle = gradient;
    ctx.fillRect(screen.x - radius, screen.y - radius, radius * 2, radius * 2);
  }

  function circuit({ point, color: rgb, kind }, index) {
    const [x, y, z] = point;
    const intensity = counts[kind] > 0 ? .49 + Math.min(Math.log2(counts[kind] + 1), 4) * .09 : .23;
    const track = [[0, -.52, 0], [x * .64, -.52, 0], [x * .64, -.52, z], [x, -.52, z], point];
    stroke(track, rgb, intensity * .62, 1.1);
    const packet = (clock * 1.2 + index * .29) % 1;
    const segment = Math.min(Math.floor(packet * (track.length - 1)), track.length - 2);
    const fraction = packet * (track.length - 1) - segment;
    const lite = track[segment].map((value, axis) => value + (track[segment + 1][axis] - value) * fraction);
    dot(project(lite), rgb, 2.4, intensity);
    halo(point, rgb, width * .09, intensity * .16);
    solid([x, y - .26, z], .43, .09, 0, rgb, intensity * .19, intensity * .7);
    solid(point, .31, .29, .13, rgb, intensity * .24, intensity);
    dot(project([x, y + .15, z]), rgb, 2, .84);
  }

  function draw() {
    if (!width || !height) return;
    ctx.clearRect(0, 0, width, height);
    const pixel = Math.min(width, height);
    halo([0, -.15, 0], PALETTE.violet, pixel * .55, .115);
    for (const [u, v, r] of dust) dot({ x: u * width, y: Math.abs(v) * height }, PALETTE.violet, r, .38);
    for (const [index, loop] of lattice.entries()) stroke(loop, PALETTE.violet, index < 6 ? .21 : .19, 1);
    for (const [index, tick] of ticks.entries()) stroke(tick, PALETTE.violet, index % 4 ? .25 : .52, 1);
    for (const axis of [-2, -1, 0, 1, 2]) {
      const span = Math.sqrt(5.8 - axis * axis);
      stroke([[axis, -.67, -span], [axis, -.67, span]], PALETTE.violet, .14);
      stroke([[-span, -.67, axis], [span, -.67, axis]], PALETTE.violet, .14);
    }
    for (const [index, satellite] of satellites.entries()) {
      const projected = project(satellite);
      const lift = .33 + .22 * Math.sin(clock * 2 + index * .5);
      stroke([[satellite[0], -.68, satellite[2]], satellite], PALETTE.violet, .17);
      dot(projected, index % 4 === 0 ? PALETTE.mint : PALETTE.violet, index % 3 ? 1.6 : 2.45, lift + .25);
    }

    const ordered = [...SIGNALS.keys()].sort((a, b) => project(SIGNALS[a].point).depth - project(SIGNALS[b].point).depth);
    for (const index of ordered) circuit(SIGNALS[index], index);
    halo([0, .12, 0], PALETTE.mint, pixel * .31, .18);
    solid([0, -.47, 0], 1.75, .18, Math.PI / 4, PALETTE.violet, .13, .68);
    solid([0, -.31, 0], 1.47, .10, Math.PI / 4, PALETTE.mint, .105, .72);
    solid([0, -.185, 0], 1.22, .06, Math.PI / 4, PALETTE.violet, .1, .54);
    solid([0, .20, 0], .91, .63, Math.PI / 4 + clock * .12, PALETTE.mint, .10, .7);
    solid([0, .20, 0], .48, .64, -.41 + clock * -.22, PALETTE.mint, .23, .9);
    solid([0, .20, 0], .25, .38, clock * .21, PALETTE.mint, .28, .96);
    dot(project([0, .24, 0]), PALETTE.mint, 3.5, .96);
    const ribbon = [[0, .92, 0], [.70, 1.16, .16], [1.36, 1.00, .71]];
    stroke(ribbon, PALETTE.mint, .38);
    dot(project(ribbon[0]), PALETTE.mint, 2, .7);
    dot(project(ribbon.at(-1)), PALETTE.mint, 2, .85);
  }

  function resize() {
    const size = canvas.getBoundingClientRect();
    const ratio = Math.min(window.devicePixelRatio || 1, 2);
    width = size.width;
    height = size.height;
    canvas.width = Math.max(1, Math.round(width * ratio));
    canvas.height = Math.max(1, Math.round(height * ratio));
    ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
    draw();
  }

  function updateControl() {
    toggle.textContent = paused ? "Resume rotation" : "Pause rotation";
    toggle.setAttribute("aria-pressed", String(paused));
    if (animation) cancelAnimationFrame(animation);
    animation = 0;
    lastFrame = 0;
    if (!paused && inView && !document.hidden) animation = requestAnimationFrame(animate);
  }

  function animate(now) {
    const elapsed = now - (lastFrame || now - 34);
    if (elapsed >= 31 && !drag) {
      const seconds = Math.min(elapsed, 75) / 1000;
      clock += seconds;
      yaw += seconds * .074;
      lastFrame = now;
      draw();
    }
    animation = requestAnimationFrame(animate);
  }

  function orbit(azimuth, elevation) {
    yaw += azimuth;
    pitch = clamp(pitch + elevation, -.1, 1.10);
    draw();
  }

  canvas.addEventListener("pointerdown", (event) => {
    if (event.button !== 0) return;
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY };
    canvas.setPointerCapture(event.pointerId);
    canvas.classList.add("is-dragging");
  });
  canvas.addEventListener("pointermove", (event) => {
    if (!drag || event.pointerId !== drag.id) return;
    orbit((event.clientX - drag.x) * .009, (drag.y - event.clientY) * .007);
    drag.x = event.clientX;
    drag.y = event.clientY;
  });
  const release = () => {
    drag = null;
    canvas.classList.remove("is-dragging");
  };
  canvas.addEventListener("pointerup", release);
  canvas.addEventListener("pointercancel", release);
  canvas.addEventListener("lostpointercapture", release);
  canvas.addEventListener("keydown", (event) => {
    const changes = { ArrowLeft: [-.13, 0], ArrowRight: [.13, 0], ArrowUp: [0, .13], ArrowDown: [0, -.13] };
    if (changes[event.key]) {
      event.preventDefault();
      orbit(...changes[event.key]);
    }
  });
  toggle.addEventListener("click", () => {
    userChoice = true;
    paused = !paused;
    updateControl();
  });
  preference.addEventListener("change", () => {
    if (!userChoice) paused = preference.matches;
    updateControl();
  });
  document.addEventListener("visibilitychange", updateControl);
  new ResizeObserver(resize).observe(canvas);
  new IntersectionObserver(([entry]) => {
    inView = entry.isIntersecting;
    updateControl();
  }).observe(canvas);

  resize();
  updateControl();
  return {
    update(nextCounts) {
      counts = nextCounts;
      draw();
    },
  };
}
