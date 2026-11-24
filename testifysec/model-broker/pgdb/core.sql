-- Labels and dominance, shared by every component's marked tables.
--
-- A label is a marking in its lattice form (marking.LatticeOf): sorted sets, never NULL, and the
-- release and display lists expanded to countries (NULL means unrestricted). The service computes
-- it from the marking package; the database only compares. badger.dominates is the rule on that
-- form, and the contract vectors check it against the marking package (pgdb tests).
CREATE SCHEMA badger;

CREATE TYPE badger.label AS (
    level      int,
    sci        text[],
    sap        text[],
    aea        text[],
    nonic      text[],
    controls   text[],
    has_fgi    boolean,
    fgi        text[],
    categories text[],
    release    text[],
    display    text[]
);

CREATE FUNCTION badger.text_set(a jsonb) RETURNS text[]
    LANGUAGE sql IMMUTABLE STRICT AS
$$ SELECT coalesce(array_agg(DISTINCT x ORDER BY x), '{}') FROM jsonb_array_elements_text(a) AS x $$;

-- label_of reads the service's JSON form. A missing or mistyped field is an error, never an
-- empty set: an empty set would make a row look lower than it is.
CREATE FUNCTION badger.label_of(j jsonb) RETURNS badger.label
    LANGUAGE plpgsql IMMUTABLE STRICT AS
$$
DECLARE
    k text;
BEGIN
    IF jsonb_typeof(j) <> 'object'
        OR NOT j ?& ARRAY['level', 'sci', 'sap', 'aea', 'nonic', 'controls', 'has_fgi', 'fgi', 'categories', 'release', 'display']
        OR jsonb_typeof(j->'level') <> 'number' OR jsonb_typeof(j->'has_fgi') <> 'boolean' THEN
        RAISE EXCEPTION 'badger.label_of: malformed label';
    END IF;
    FOREACH k IN ARRAY ARRAY['sci', 'sap', 'aea', 'nonic', 'controls', 'fgi', 'categories'] LOOP
        IF jsonb_typeof(j->k) <> 'array' THEN
            RAISE EXCEPTION 'badger.label_of: % must be a list', k;
        END IF;
    END LOOP;
    FOREACH k IN ARRAY ARRAY['release', 'display'] LOOP
        IF jsonb_typeof(j->k) NOT IN ('array', 'null') THEN
            RAISE EXCEPTION 'badger.label_of: % must be a list or null', k;
        END IF;
    END LOOP;
    RETURN ROW(
        (j->>'level')::int,
        badger.text_set(j->'sci'), badger.text_set(j->'sap'), badger.text_set(j->'aea'),
        badger.text_set(j->'nonic'), badger.text_set(j->'controls'),
        (j->>'has_fgi')::boolean, badger.text_set(j->'fgi'), badger.text_set(j->'categories'),
        CASE WHEN jsonb_typeof(j->'release') = 'null' THEN NULL ELSE badger.text_set(j->'release') END,
        CASE WHEN jsonb_typeof(j->'display') = 'null' THEN NULL ELSE badger.text_set(j->'display') END
    )::badger.label;
END
$$;

-- dominates(a, b): a system at a may hold content marked b. It is the marking package's
-- Dominates on the lattice form (marking.Lattice). STRICT: an unknown label dominates nothing.
CREATE FUNCTION badger.dominates(a badger.label, b badger.label) RETURNS boolean
    LANGUAGE sql IMMUTABLE STRICT AS
$$
SELECT (a).level >= (b).level
   AND (a).sci @> (b).sci AND (a).sap @> (b).sap AND (a).aea @> (b).aea
   AND (a).nonic @> (b).nonic AND (a).controls @> (b).controls
   AND (NOT (b).has_fgi OR ((a).has_fgi AND (cardinality((a).fgi) = 0
        OR (cardinality((b).fgi) > 0 AND (a).fgi @> (b).fgi))))
   AND ((a).level >= 2 OR (a).categories @> (b).categories)
   AND ((b).release IS NULL OR ((a).release IS NOT NULL AND (a).release <@ (b).release))
   AND ((b).display IS NULL OR ((a).display IS NOT NULL AND (a).display <@ (b).display))
$$;

-- session_label is the label the service set for this transaction (pgdb.Tx), or NULL when none
-- was set: with no label, no marked row is visible and none can be written.
CREATE FUNCTION badger.session_label() RETURNS badger.label
    LANGUAGE sql STABLE AS
$$
SELECT CASE WHEN coalesce(current_setting('badger.label', true), '') = '' THEN NULL
            ELSE badger.label_of(current_setting('badger.label', true)::jsonb) END
$$;

-- visible and writable are the two row-level security tests every marked table uses: read down
-- only, and write at exactly the session label (so no write down, and nothing written that the
-- writer could not read back).
CREATE FUNCTION badger.visible(row_label badger.label) RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT coalesce(badger.dominates(badger.session_label(), row_label), false) $$;

CREATE FUNCTION badger.writable(row_label badger.label) RETURNS boolean
    LANGUAGE sql STABLE AS
$$ SELECT coalesce(badger.dominates(badger.session_label(), row_label) AND badger.dominates(row_label, badger.session_label()), false) $$;

REVOKE ALL ON SCHEMA badger FROM PUBLIC;
GRANT USAGE ON SCHEMA badger TO {{service}};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA badger FROM PUBLIC;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA badger TO {{service}};
