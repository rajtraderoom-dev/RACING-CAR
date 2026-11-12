BEGIN;
CREATE FUNCTION protect_collection_child() RETURNS trigger LANGUAGE plpgsql AS $$ DECLARE cid uuid; BEGIN cid=CASE WHEN TG_OP='DELETE' THEN OLD.collection_id ELSE NEW.collection_id END; IF EXISTS(SELECT 1 FROM cash_collections WHERE id=cid AND state='APPROVED') THEN RAISE EXCEPTION 'approved custody is immutable'; END IF; IF TG_OP='DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$;
CREATE TRIGGER positions_after_approval BEFORE INSERT OR UPDATE OR DELETE ON custody_positions FOR EACH ROW EXECUTE FUNCTION protect_collection_child();
CREATE TRIGGER attachments_after_approval BEFORE INSERT OR UPDATE OR DELETE ON attachments FOR EACH ROW EXECUTE FUNCTION protect_collection_child();
CREATE TRIGGER allocations_after_approval BEFORE INSERT OR UPDATE OR DELETE ON handover_allocations FOR EACH ROW EXECUTE FUNCTION protect_collection_child();
INSERT INTO schema_migrations VALUES(3);
COMMIT;
